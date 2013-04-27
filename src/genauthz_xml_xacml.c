#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>

#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_pdp.h"
#include "genauthz_xacml.h"
#include "genauthz_normalized_xacml.h"
#include "genauthz_xml_xacml.h"

#include <string.h>
#include <libxml/tree.h>
#include <libxml/parser.h>


static void
trim(xmlChar *str) {
    int i;

    for (i = xmlStrlen(str) - 1; 0 <= i; i--) {
        if ((str[i] == '\r') ||
            (str[i] == '\n') ||
            (str[i] == ' ')) {
            str[i] = '\0';
        }
        else {
            break;
        }
    }
}

void
walk_ns(xmlNs *ns) {
    if (ns == NULL)
        return;

    printf("ns-href: %s, ", ns->href);
    printf("ns-prefix: %s, ", ns->prefix);

    return walk_ns(ns->next);
}

void
walk_properties(struct _xmlAttr *xa) {
    if (xa == NULL)
        return;

    printf("property-name: %s, ", xa->name);
    walk(xa->children, 10);
    walk_properties(xa->next);
}

void
walk(xmlNodePtr node, int depth) {
    xmlChar buf[64];
    xmlChar content[128];
    xmlNode *cur_node = NULL;
    int i = 0;

    /* Indent space */
    for (i = 0; i < (depth * 2); i++) {
        buf[i] = ' ';
    }
    buf[i] = '\0';

    for (cur_node = node; cur_node; cur_node = cur_node->next) {
        printf("%s", buf);

        /* Type */
        printf("type(%d):", cur_node->type);
        switch (cur_node->type) {
            case XML_ELEMENT_NODE:
                printf("Node, ");
                break;
            case XML_ATTRIBUTE_NODE:
                printf("Attribute, ");
                break;
            case XML_TEXT_NODE:
                printf("Text, ");
                break;
            default:
                printf("Other, ");
                break;
        }

        /* Name of node, or entity */
        printf("name:%s, ", cur_node->name);
        if (cur_node->nsDef == NULL)
            printf("no-nsdef, ");
        walk_ns(cur_node->nsDef);
        if (cur_node->ns == NULL)
            printf("no-ns, ");
        walk_ns(cur_node->ns);
        walk_properties(cur_node->properties);

        /* Content */
        if (NULL == cur_node->content) {
            printf("content:(null)");
        }
        else {
            memcpy(content, cur_node->content, xmlStrlen(cur_node->content));
            trim(content);
            printf("content:%s", content);
        }
        printf("\n");

        walk(cur_node->children, depth + 1);
    }
}

static ga_xacml_datatype_t
xmldatatype2normalizeddatatype(const xmlChar *xmldt) {
    if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#string", xmldt)) return GA_XACML_DATATYPE_STRING;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#boolean", xmldt)) return GA_XACML_DATATYPE_BOOLEAN;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#float", xmldt)) return GA_XACML_DATATYPE_FLOAT;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#double", xmldt)) return GA_XACML_DATATYPE_DOUBLE;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#decimal", xmldt)) return GA_XACML_DATATYPE_DECIMAL;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#duration", xmldt)) return GA_XACML_DATATYPE_DURATION;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#datetime", xmldt)) return GA_XACML_DATATYPE_DATETIME;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#time", xmldt)) return GA_XACML_DATATYPE_TIME;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#date", xmldt)) return GA_XACML_DATATYPE_DATE;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#gyearmonth", xmldt)) return GA_XACML_DATATYPE_GYEARMONTH;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#gyear", xmldt)) return GA_XACML_DATATYPE_GYEAR;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#gmonthday", xmldt)) return GA_XACML_DATATYPE_GMONTHDAY;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#gday", xmldt)) return GA_XACML_DATATYPE_GDAY;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#gmonth", xmldt)) return GA_XACML_DATATYPE_GMONTH;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#hexbinary", xmldt)) return GA_XACML_DATATYPE_HEXBINARY;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#base64binary", xmldt)) return GA_XACML_DATATYPE_BASE64BINARY;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#anyuri", xmldt)) return GA_XACML_DATATYPE_ANYURI;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#qname", xmldt)) return GA_XACML_DATATYPE_QNAME;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#notation", xmldt)) return GA_XACML_DATATYPE_NOTATION;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#derived", xmldt)) return GA_XACML_DATATYPE_DERIVED;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#token", xmldt)) return GA_XACML_DATATYPE_TOKEN;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#language", xmldt)) return GA_XACML_DATATYPE_LANGUAGE;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#id", xmldt)) return GA_XACML_DATATYPE_ID;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#integer", xmldt)) return GA_XACML_DATATYPE_INTEGER;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#long", xmldt)) return GA_XACML_DATATYPE_LONG;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#int", xmldt)) return GA_XACML_DATATYPE_INT;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#short", xmldt)) return GA_XACML_DATATYPE_SHORT;
    else if (0 == xmlStrcasecmp((const xmlChar *)"http://www.w3.org/2001/XMLSchema#byte", xmldt)) return GA_XACML_DATATYPE_BYTE;
    else return GA_XACML_DATATYPE_UNKNOWN;
}

static evhtp_res
normalize_xml2xacml_values(struct tq_xacml_attribute_s *x_attribute,
                               xmlNodePtr subsubsubroot) {
    xmlNode *cur_node = NULL;
    xmlNode *property_node = NULL;
    struct tq_xacml_attribute_value_s *value;

    TAILQ_INIT(&(x_attribute->values));

    if (subsubsubroot == NULL) {
        return EVHTP_RES_200;
    }

    for (cur_node = subsubsubroot; cur_node; cur_node = cur_node->next) {
        /* Filter the nodes to select value headers */
        if (cur_node->type == XML_ELEMENT_NODE && cur_node->name &&
            xmlStrcasecmp(cur_node->name, (const xmlChar *)"attributevalue") == 0 &&
            cur_node->properties && cur_node->properties->name &&
            xmlStrcasecmp(cur_node->properties->name, (const xmlChar *)"datatype") == 0 &&
            cur_node->properties->children) {

            property_node = cur_node->properties->children;
            if (xmlStrcasecmp(property_node->name, (const xmlChar *)"text") == 0) {
                value = malloc(sizeof(struct tq_xacml_attribute_value_s));
                if (value == NULL) {
                    return EVHTP_RES_SERVERR;
                }
                value->datatype = xmldatatype2normalizeddatatype(property_node->content);
                value->datatype_id = xmlStrdup(property_node->content);

                /* printf("-> datatype: %s", property_node->content); */
                /* printf(", %s\n", value->datatype == GA_XACML_DATATYPE_STRING ?
                                                       "GA_XACML_DATATYPE_STRING" : "other"); */
                /* printf("-> value: %s\n", cur_node->children->content); */

                /* TODO: should convert/cast */
                value->data = xmlStrdup(cur_node->children->content);
            }
            TAILQ_INSERT_TAIL(&(x_attribute->values), value, next);
        }
    }
    return EVHTP_RES_200;
}


static evhtp_res
normalize_xml2xacml_attributes(struct tq_xacml_category_s *x_category,
                               xmlNodePtr subsubroot) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    xmlNode *cur_node = NULL;
    xmlNode *property_node = NULL;
    xmlAttr *tmp_node = NULL;
    struct tq_xacml_attribute_s *x_attribute;

    TAILQ_INIT(&(x_category->attributes));

    if (subsubroot == NULL) {
        return EVHTP_RES_200;
    }

    for (cur_node = subsubroot; cur_node; cur_node = cur_node->next) {
        /* Filter the nodes to select attribute headers */

        if (cur_node->type == XML_ELEMENT_NODE && cur_node->name &&
            xmlStrcasecmp(cur_node->name, (const xmlChar *)"attribute") == 0 &&
            cur_node->properties && cur_node->properties->name &&
            xmlStrcasecmp(cur_node->properties->name, (const xmlChar *)"attributeid") == 0) {


            property_node = cur_node->properties->children;
            if (property_node &&
                xmlStrcasecmp(property_node->name, (const xmlChar *)"text") == 0) {

                x_attribute = malloc(sizeof(struct tq_xacml_attribute_s));
                if (x_attribute == NULL) {
                    return EVHTP_RES_SERVERR;
                }

                x_attribute->include_in_result = GA_XACML_NO;
                for (tmp_node = cur_node->properties; tmp_node; tmp_node = tmp_node->next) {
                    if (tmp_node->type == XML_ATTRIBUTE_NODE &&
                        xmlStrcasecmp(tmp_node->name, (const xmlChar *)"includeinresult") == 0) {

                        if (tmp_node->children && tmp_node->children->name &&
                            xmlStrcasecmp(tmp_node->children->name, (const xmlChar *)"text") == 0) {

                            if (tmp_node->children->content &&
                                xmlStrcasecmp(tmp_node->children->content, (const xmlChar *)"true") == 0) {
                                x_attribute->include_in_result = GA_XACML_YES;
                            }
                        }
                    }
                }

                x_attribute->id = xmlStrdup(property_node->content);
                if (x_attribute->id == NULL) {
                    return EVHTP_RES_SERVERR;
                }

                http_res = normalize_xml2xacml_values(x_attribute, cur_node->children);
                if (http_res != EVHTP_RES_200) {
                    return http_res;
                }
            }
            TAILQ_INSERT_TAIL(&(x_category->attributes), x_attribute, next);
        }
    }
    return EVHTP_RES_200;
}

static evhtp_res
normalize_xml2xacml_categories(struct tq_xacml_request_s *request,
                               xmlNodePtr subroot) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    xmlNode *cur_node = NULL;
    xmlNode *property_node = NULL;
    struct tq_xacml_category_s *category;
    const xmlChar *cat;

    if (subroot == NULL)
        return EVHTP_RES_BADREQ;

    TAILQ_INIT(&(request->categories));

    for (cur_node = subroot; cur_node; cur_node = cur_node->next) {
        /* Filter the nodes to select category headers */
        if (cur_node->type == XML_ELEMENT_NODE && cur_node->name &&
            xmlStrcasecmp(cur_node->name, (const xmlChar *)"attributes") == 0 &&
            cur_node->properties && cur_node->properties->name &&
            xmlStrcasecmp(cur_node->properties->name, (const xmlChar *)"category") == 0) {

            property_node = cur_node->properties->children;
            if (xmlStrcasecmp(property_node->name, (const xmlChar *)"text") == 0) {
                category = malloc(sizeof(struct tq_xacml_category_s));
                if (category == NULL) {
                    return EVHTP_RES_SERVERR;
                }

                category->id = xmlStrdup(property_node->content);
                /* category parser */
                if (xmlStrncasecmp(category->id, (const xmlChar *)"urn:oasis:names:tc:xacml:",
                                          xmlStrlen((const xmlChar *)"urn:oasis:names:tc:xacml:")) == 0) {

                    cat = &category->id[xmlStrlen((const xmlChar *)"urn:oasis:names:tc:xacml:")];

                    /* Move beyond XACML version */
                    cat = xmlStrchr(cat, ':');
                    cat = &cat[1];
                    /* Move beyond category statement */
                    cat = xmlStrchr(cat, ':');
                    cat = &cat[1];

                    /* Get the category name */
                    if (xmlStrcasecmp(cat, (const xmlChar *)"environment") == 0) {
                        category->type = GA_XACML_CATEGORY_ENVIRONMENT;
                    } else if (xmlStrcasecmp(cat, (const xmlChar *)"access-subject") == 0) {
                        category->type = GA_XACML_CATEGORY_SUBJECT;
                    } else if (xmlStrcasecmp(cat, (const xmlChar *)"action") == 0) {
                        category->type = GA_XACML_CATEGORY_ACTION;
                    } else if (xmlStrcasecmp(cat, (const xmlChar *)"resource") == 0) {
                        category->type = GA_XACML_CATEGORY_RESOURCE;
                    } else {
                        category->type = GA_XACML_CATEGORY_UNKNOWN;
                    }
                }
                /* printf("id: %s\n", category->id); */

                /* Extract all the attributes */
                TAILQ_INIT(&(category->attributes));
                http_res = normalize_xml2xacml_attributes(category, cur_node->children);
                TAILQ_INSERT_TAIL(&(request->categories), category, next);

                if (http_res != EVHTP_RES_200) {
                    break;
                }
            }
        }
    }

    return http_res;
}


static evhtp_res
normalize_xml2xacml(struct tq_xacml_request_s *request,
                    xmlNodePtr root_element) {

    if (request == NULL || root_element == NULL)
        return EVHTP_RES_SERVERR;

    /* Check if we've got a Request */
    if (xmlStrcasecmp(root_element->name, (const xmlChar *)"request") != 0) {
        return EVHTP_RES_BADREQ;
    }

    /* Check and record the XACML namespace */
    if (root_element && root_element->ns && root_element->ns->href) {
        request->ns = xmlStrdup(root_element->ns->href);
    }

    /* Pull out categorized attributes */
    normalize_xml2xacml_categories(request, root_element->children);

    return EVHTP_RES_200;
}



evhtp_res
pdp_xml_input_processor(struct tq_xacml_request_s **xacml_req,
                        evhtp_request_t *evhtp_req) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    xmlDocPtr  doc;
    xmlNodePtr root_element = NULL;
    unsigned char *buf = NULL;


    syslog(LOG_DEBUG, "%s: %s", __func__, buf);
    LIBXML_TEST_VERSION;

    /* Read document */
    doc = xmlReadMemory((char *)evpull(evhtp_req->buffer_in),
                        evbuffer_get_length(evhtp_req->buffer_in),
                        NULL,
                        NULL,
                        0);
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse\n");
        goto final;
    }

    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);

    /* Make me a request */
    *xacml_req = malloc(sizeof(struct tq_xacml_request_s));
    if (*xacml_req == NULL) {
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* Normalize XACML Request */
    http_res = normalize_xml2xacml(*xacml_req, root_element);
    if (http_res != EVHTP_RES_200) {
        goto final;
    }

final:
    /* Free document */
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return http_res;
}

int
normalized_xacml_attribute_values2xml_evbuffer(struct evbuffer *output,
                                           tq_xacml_attribute_value_list_t attr_value_list) {
    struct tq_xacml_attribute_value_s *value;

    TAILQ_FOREACH(value, &attr_value_list, next) {
        evbuffer_add_printf(output, "        <AttributeValue DataType=\"%s\">",
                            value->datatype_id);

        if (value->datatype == GA_XACML_DATATYPE_STRING) {
            evbuffer_add_printf(output, "%s", value->data);
        }
        evbuffer_add_printf(output, "</AttributeValue>\n");
    }
    return 0;
}

int
normalized_xacml_attributes2xml_evbuffer(struct evbuffer *output,
                                     tq_xacml_attribute_list_t attr_list) {
    struct tq_xacml_attribute_s *attribute;

    TAILQ_FOREACH(attribute, &attr_list, next) {
        evbuffer_add_printf(output, "      <Attribute IncludeInResult=\"%s\" AttributeId=\"%s\">\n",
                                    attribute->include_in_result == GA_XACML_NO ? "false" : "true",
                                    attribute->id);
        /* Output for the Attribute values */
        normalized_xacml_attribute_values2xml_evbuffer(output, attribute->values);
        evbuffer_add_printf(output, "      </Attribute>\n");
    }
    return 0;
}

int
normalized_xacml_categories2xml_evbuffer(struct evbuffer *output,
                                     tq_xacml_category_list_t cat_list) {
    struct tq_xacml_category_s *category;

    TAILQ_FOREACH(category, &cat_list, next) {
        switch (category->type) {
            case GA_XACML_CATEGORY_OBLIGATION:
                evbuffer_add_printf(output,
                                    "      <Obligation ObligationId=\"%s\">\n",
                                    category->id);
                break;
            case GA_XACML_CATEGORY_ADVICE:
                evbuffer_add_printf(output,
                                    "      <Advice AdviceId=\"%s\">\n",
                                    category->id);
                break;
            default:
                evbuffer_add_printf(output, "ERROR: Internal server error\n");
                return 1;
        }
        /* Output for the Attribute values */
        normalized_xacml_attributes2xml_evbuffer(output, category->attributes);
        evbuffer_add_printf(output, "      </Obligation>\n");
        switch (category->type) {
            case GA_XACML_CATEGORY_OBLIGATION:
                evbuffer_add_printf(output,
                                    "      </Obligation>\n");
                break;
            case GA_XACML_CATEGORY_ADVICE:
                evbuffer_add_printf(output,
                                    "      </Advice>\n");
                break;
            default:
                evbuffer_add_printf(output, "ERROR: Internal server error\n");
                return 1;
        }
    }
    return 0;
}

evhtp_res
pdp_xml_output_processor(struct evbuffer *output,
                         struct tq_xacml_response_s *xacml_res) {
    evhtp_res http_res = EVHTP_RES_200;

    /* Response header */
    evbuffer_add_printf(output,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<Response xmlns=\"%s\" "
            "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
            "xsi:schemaLocation=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 "
            "http://docs.oasis-open.org/xacml/3.0/xacml-core-v3-schema-wd-17.xsd\">\n",
                xacml_res->ns ? (char *)xacml_res->ns : "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17");

    /* Result */
    evbuffer_add_printf(output,
            "  <Result>\n");
    /* Decision */
    evbuffer_add_printf(output,
            "    <Decision>%s</Decision>\n", xacml_decision2str(xacml_res->decision));
    /* Obligations */
    if (!(TAILQ_EMPTY(&(xacml_res->obligations)))) {
        evbuffer_add_printf(output, "    <Obligations>\n");
        normalized_xacml_categories2xml_evbuffer(output, xacml_res->obligations);
        evbuffer_add_printf(output, "    </Obligations>\n");
    }
    /* Associated Advice */
    if (!(TAILQ_EMPTY(&(xacml_res->advices)))) {
        evbuffer_add_printf(output, "    <AssociatedAdvice>\n");
        normalized_xacml_categories2xml_evbuffer(output, xacml_res->advices);
        evbuffer_add_printf(output, "    </AssociatedAdvice>\n");
    }
    /* IncludeInResult Attributes */
    if (!(TAILQ_EMPTY(&(xacml_res->attributes)))) {
        evbuffer_add_printf(output, "    <Attributes>\n");
        normalized_xacml_attributes2xml_evbuffer(output, xacml_res->attributes);
        evbuffer_add_printf(output, "    </Attributes>\n");
    }

    /* Finalize */
    evbuffer_add_printf(output,
            "  </Result>\n");
    evbuffer_add_printf(output,
            "</Response>\n");

    return http_res;
}

