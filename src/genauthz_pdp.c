#include <sys/types.h>
#include <pwd.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <syslog.h>
#include <stdio.h>
#include <evhtp.h>
#include <expat.h>

#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_pdp.h"
#include "genauthz_xacml.h"

#include <string.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

void trim(char *str)
{
    int i;

    for (i = strlen(str) - 1; 0 <= i; i--) {
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

void walk_ns(xmlNs *ns) {
    if (ns == NULL)
        return;

    printf("ns-href: %s, ", ns->href);
    printf("ns-prefix: %s, ", ns->prefix);

    return walk_ns(ns->next);
}

void walk(xmlNodePtr node, int depth);

void walk_properties(struct _xmlAttr *xa) {
    if (xa == NULL)
        return;

    printf("property-name: %s, ", xa->name);
    walk(xa->children, 10);
    walk_properties(xa->next);
}

void walk(xmlNodePtr node, int depth)
{
    char     buf[64];
    char     content[128];
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
            strcpy(content, cur_node->content);
            trim(content);
            printf("content:%s", content);
        }
        printf("\n");

        walk(cur_node->children, depth + 1);
    }
}

static ga_xacml_datatype_t
xmldatatype2normalizeddatatype(const char *xmldt) {
    if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#string", xmldt)) return GA_XACML_DATATYPE_STRING;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#boolean", xmldt)) return GA_XACML_DATATYPE_BOOLEAN;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#float", xmldt)) return GA_XACML_DATATYPE_FLOAT;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#double", xmldt)) return GA_XACML_DATATYPE_DOUBLE;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#decimal", xmldt)) return GA_XACML_DATATYPE_DECIMAL;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#duration", xmldt)) return GA_XACML_DATATYPE_DURATION;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#datetime", xmldt)) return GA_XACML_DATATYPE_DATETIME;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#time", xmldt)) return GA_XACML_DATATYPE_TIME;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#date", xmldt)) return GA_XACML_DATATYPE_DATE;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#gyearmonth", xmldt)) return GA_XACML_DATATYPE_GYEARMONTH;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#gyear", xmldt)) return GA_XACML_DATATYPE_GYEAR;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#gmonthday", xmldt)) return GA_XACML_DATATYPE_GMONTHDAY;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#gday", xmldt)) return GA_XACML_DATATYPE_GDAY;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#gmonth", xmldt)) return GA_XACML_DATATYPE_GMONTH;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#hexbinary", xmldt)) return GA_XACML_DATATYPE_HEXBINARY;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#base64binary", xmldt)) return GA_XACML_DATATYPE_BASE64BINARY;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#anyuri", xmldt)) return GA_XACML_DATATYPE_ANYURI;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#qname", xmldt)) return GA_XACML_DATATYPE_QNAME;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#notation", xmldt)) return GA_XACML_DATATYPE_NOTATION;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#derived", xmldt)) return GA_XACML_DATATYPE_DERIVED;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#token", xmldt)) return GA_XACML_DATATYPE_TOKEN;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#language", xmldt)) return GA_XACML_DATATYPE_LANGUAGE;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#id", xmldt)) return GA_XACML_DATATYPE_ID;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#integer", xmldt)) return GA_XACML_DATATYPE_INTEGER;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#long", xmldt)) return GA_XACML_DATATYPE_LONG;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#int", xmldt)) return GA_XACML_DATATYPE_INT;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#short", xmldt)) return GA_XACML_DATATYPE_SHORT;
    else if (0 == strcasecmp("http://www.w3.org/2001/XMLSchema#byte", xmldt)) return GA_XACML_DATATYPE_BYTE;
    else return GA_XACML_DATATYPE_UNKNOWN;
}

static evhtp_res
normalize_xml2xacml_values(struct tq_xacml_attribute_s *attribute,
                               xmlNodePtr subsubsubroot) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    xmlNode *cur_node = NULL;
    xmlNode *property_node = NULL;
    xmlNode *node_value = NULL;
    struct tq_xacml_attribute_value_s *value;

    TAILQ_INIT(&(attribute->values));

    if (subsubsubroot == NULL) {
        return EVHTP_RES_200;
    }

    for (cur_node = subsubsubroot; cur_node; cur_node = cur_node->next) {
        /* Filter the nodes to select value headers */
        if (cur_node->type == XML_ELEMENT_NODE && cur_node->name &&
            strcasecmp(cur_node->name, "attributevalue") == 0 &&
            cur_node->properties && cur_node->properties->name &&
            strcasecmp(cur_node->properties->name, "datatype") == 0 &&
            cur_node->properties->children) {

            property_node = cur_node->properties->children;
            if (strcasecmp(property_node->name, "text") == 0) {
                value = malloc(sizeof(struct tq_xacml_attribute_value_s));
                if (value == NULL) {
                    return EVHTP_RES_SERVERR;
                }
                value->datatype = xmldatatype2normalizeddatatype(property_node->content);
                value->datatype_id = strdup(property_node->content);

                /* printf("-> datatype: %s", property_node->content); */
                /* printf(", %s\n", value->datatype == GA_XACML_DATATYPE_STRING ?
                                                       "GA_XACML_DATATYPE_STRING" : "other"); */
                /* printf("-> value: %s\n", cur_node->children->content); */

                /* TODO: should convert/cast */
                value->data = strdup(cur_node->children->content);
            }
            TAILQ_INSERT_TAIL(&(attribute->values), value, entries);
        }
    }
    return EVHTP_RES_200;
}


static evhtp_res
normalize_xml2xacml_attributes(struct tq_xacml_category_s *category,
                               xmlNodePtr subsubroot) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    xmlNode *cur_node = NULL;
    xmlNode *property_node = NULL;
    xmlNode *node_value = NULL;
    struct tq_xacml_attribute_s *attribute;

    TAILQ_INIT(&(category->attributes));

    if (subsubroot == NULL) {
        return EVHTP_RES_200;
    }

    for (cur_node = subsubroot; cur_node; cur_node = cur_node->next) {
        /* Filter the nodes to select attribute headers */

        if (cur_node->type == XML_ELEMENT_NODE && cur_node->name &&
            strcasecmp(cur_node->name, "attribute") == 0 &&
            cur_node->properties && cur_node->properties->name &&
            strcasecmp(cur_node->properties->name, "attributeid") == 0) {

            property_node = cur_node->properties->children;
            if (strcasecmp(property_node->name, "text") == 0) {
                attribute = malloc(sizeof(struct tq_xacml_attribute_s));
                if (attribute == NULL) {
                    return EVHTP_RES_SERVERR;
                }
                /* printf("-> attributeid: %s\n", property_node->content); */

                attribute->id = strdup(property_node->content);
                if (attribute->id == NULL) {
                    return EVHTP_RES_SERVERR;
                }

                http_res = normalize_xml2xacml_values(attribute, cur_node->children);
                if (http_res != EVHTP_RES_200) {
                    return http_res;
                }
            }
            TAILQ_INSERT_TAIL(&(category->attributes), attribute, entries);
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
    char *cat;

    if (subroot == NULL)
        return EVHTP_RES_BADREQ;

    TAILQ_INIT(&(request->categories));

    for (cur_node = subroot; cur_node; cur_node = cur_node->next) {
        /* Filter the nodes to select category headers */
        if (cur_node->type == XML_ELEMENT_NODE && cur_node->name &&
            strcasecmp(cur_node->name, "attributes") == 0 &&
            cur_node->properties && cur_node->properties->name &&
            strcasecmp(cur_node->properties->name, "category") == 0) {

            property_node = cur_node->properties->children;
            if (strcasecmp(property_node->name, "text") == 0) {
                category = malloc(sizeof(struct tq_xacml_category_s));
                if (category == NULL) {
                    return EVHTP_RES_SERVERR;
                }

                category->id = strdup(property_node->content);
                /* category parser */
                if (strncasecmp(category->id, "urn:oasis:names:tc:xacml:",
                                       strlen("urn:oasis:names:tc:xacml:")) == 0) {
                    cat = &category->id[strlen("urn:oasis:names:tc:xacml:")];

                    /* Move beyond XACML version */
                    cat = strchr(cat, ':');
                    cat = &cat[1];
                    /* Move beyond category statement */
                    cat = strchr(cat, ':');
                    cat = &cat[1];

                    /* Get the category name */
                    if (strcasecmp(cat, "environment") == 0) {
                        category->type = GA_XACML_CATEGORY_ENVIRONMENT;
                    } else if (strcasecmp(cat, "access-subject") == 0) {
                        category->type = GA_XACML_CATEGORY_SUBJECT;
                    } else if (strcasecmp(cat, "action") == 0) {
                        category->type = GA_XACML_CATEGORY_ACTION;
                    } else if (strcasecmp(cat, "resource") == 0) {
                        category->type = GA_XACML_CATEGORY_RESOURCE;
                    } else {
                        category->type = GA_XACML_CATEGORY_UNKNOWN;
                    }
                }
                /* printf("id: %s\n", category->id); */

                /* Extract all the attributes */
                TAILQ_INIT(&(category->attributes));
                http_res = normalize_xml2xacml_attributes(category, cur_node->children);
                TAILQ_INSERT_TAIL(&(request->categories), category, entries);

                if (http_res != EVHTP_RES_200) {
                    break;
                }
            }
        }
    }

    return http_res;
}

char *
xacml_category_type2str(enum ga_xacml_category_e type) {
    switch (type) {
        case GA_XACML_CATEGORY_ENVIRONMENT:
            return "environment";
        case GA_XACML_CATEGORY_SUBJECT:
            return "subject";
        case GA_XACML_CATEGORY_ACTION:
            return "action";
        case GA_XACML_CATEGORY_RESOURCE:
            return "resource";
        case GA_XACML_CATEGORY_UNKNOWN:
        default:
            return "unknown";
    }
    return "unknown";
}

void
print_normalized_xacml_request(struct tq_xacml_request_s *request) {
    struct tq_xacml_category_s *category;
    struct tq_xacml_attribute_s *attribute;
    struct tq_xacml_attribute_value_s *value;

    printf("XACML Request NS: %s\n", request->ns);
    for (category = TAILQ_FIRST(&(request->categories));
         category != NULL; category = TAILQ_NEXT(category, entries)) {
        printf(" Category ID: %s\n", category->id);
        printf(" Category type: %s\n", xacml_category_type2str(category->type));
        for (attribute = TAILQ_FIRST(&(category->attributes));
             attribute != NULL; attribute = TAILQ_NEXT(attribute, entries)) {
            printf("  Attribute ID: %s\n", attribute->id);
            for (value = TAILQ_FIRST(&(attribute->values));
                 value != NULL; value = TAILQ_NEXT(value, entries)) {
                printf("   Datatype ID: %s\n", value->datatype_id);
                if (value->datatype == GA_XACML_DATATYPE_STRING) {
                    printf("   Data: \"%s\"\n", (char *)value->data);
                }

            }
        }
    }

}

static evhtp_res
normalize_xml2xacml(struct tq_xacml_request_s *request,
                    xmlNodePtr root_element) {

    if (request == NULL || root_element == NULL)
        return EVHTP_RES_SERVERR;

    /* Check if we've got a Request */
    if (strcasecmp(root_element->name, "request") != 0) {
        return EVHTP_RES_BADREQ;
    }

    /* Check and record the XACML namespace */
    if (root_element && root_element->ns && root_element->ns->href) {
        request->ns = strdup(root_element->ns->href);
    }

    /* Pull out categorized attributes */
    normalize_xml2xacml_categories(request, root_element->children);

    /* Print the normalized XACML Request */
    print_normalized_xacml_request(request);

    return EVHTP_RES_200;
}



static evhtp_res
pdp_xml_processor(evhtp_request_t *req) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    size_t bufsize = 0;
    xmlDocPtr  doc;
    xmlNodePtr root_element = NULL;
    struct tq_xacml_request_s *request = NULL;
    unsigned char *buf = NULL;


    syslog(LOG_DEBUG, "%s: %s", __func__, buf);
    LIBXML_TEST_VERSION;

    /* Read document */
    doc = xmlReadMemory(evpull(req->buffer_in),
                        evbuffer_get_length(req->buffer_in),
                        NULL,
                        NULL,
                        0);
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse\n");
        return;
    }

    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);

    /* Make me a request */
    request = malloc(sizeof(struct tq_xacml_request_s));
    if (request == NULL) {
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* Normalize XACML Request */
    http_res = normalize_xml2xacml(request, root_element);
    if (http_res != EVHTP_RES_200) {
        goto final;
    }

final:
    /* Free document */
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return http_res;
}

void
pdp_cb(evhtp_request_t * req, void * a) {
    evhtp_res http_res = EVHTP_RES_SERVERR;

    if (!req) {
        syslog(LOG_ERR, "No request object! - problem in evhtp/libevent\n");
        return;
    }
    if (!req->conn) {
        syslog(LOG_ERR, "No connection object in request object - problem in evhtp/libevent\n");
        return;
    }

    /* Only accept a POST */
    if (req->method != htp_method_POST) {
        http_res = EVHTP_RES_METHNALLOWED;
        goto final;
    }
    syslog(LOG_DEBUG, "%s", __func__);


    /* Which output is selected */
    switch (accept_format(req)) {
        case TYPE_APP_XACML_XML:
        case TYPE_APP_ALL:
            syslog(LOG_DEBUG, "pdp xml");
            http_res = pdp_xml_processor(req);
            goto final;
        default:
            /* syslog: source made a bad request */
            http_res = EVHTP_RES_UNSUPPORTED;
            goto final;
    }

final:
    evhtp_send_reply(req, http_res);
    return;
}
