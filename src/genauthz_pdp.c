#include <sys/types.h>
#include <pwd.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <syslog.h>
#include <stdio.h>
#include <evhtp.h>

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
            TAILQ_INSERT_TAIL(&(attribute->values), value, next);
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
            TAILQ_INSERT_TAIL(&(category->attributes), attribute, next);
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
                TAILQ_INSERT_TAIL(&(request->categories), category, next);

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
         category != NULL; category = TAILQ_NEXT(category, next)) {
        printf(" Category ID: %s\n", category->id);
        printf(" Category type: %s\n", xacml_category_type2str(category->type));
        for (attribute = TAILQ_FIRST(&(category->attributes));
             attribute != NULL; attribute = TAILQ_NEXT(attribute, next)) {
            printf("  Attribute ID: %s\n", attribute->id);
            for (value = TAILQ_FIRST(&(attribute->values));
                 value != NULL; value = TAILQ_NEXT(value, next)) {
                printf("   Datatype ID: %s\n", value->datatype_id);
                if (value->datatype == GA_XACML_DATATYPE_STRING) {
                    printf("   Data: \"%s\"\n", (char *)value->data);
                }
            }
        }
    }
}

void
delete_normalized_xacml_attribute(struct tq_xacml_attribute_s *attribute) {
    struct tq_xacml_attribute_value_s *value, *value_tmp;

    if (attribute == NULL)
        return;

    free(attribute->id);

    TAILQ_FOREACH_SAFE(value, &attribute->values, next, value_tmp) {
        TAILQ_REMOVE(&(attribute->values), value, next);

        /* TODO: Think of possible casting of native datatypes */
        free(value->data);
        free(value->datatype_id);
        memset(value, 0, sizeof(struct tq_xacml_attribute_value_s));
        free(value);
    }
    memset(attribute, 0, sizeof(struct tq_xacml_attribute_s));
}

void
delete_normalized_xacml_category(struct tq_xacml_category_s *category) {
    struct tq_xacml_attribute_s *attribute, *attribute_tmp;

    if (category == NULL)
        return;

    free(category->id);

    TAILQ_FOREACH_SAFE(attribute, &category->attributes, next, attribute_tmp) {
        TAILQ_REMOVE(&(category->attributes), attribute, next);
        delete_normalized_xacml_attribute(attribute);
        free(attribute);
    }
    memset(category, 0, sizeof(struct tq_xacml_category_s));
}

void
delete_normalized_xacml_response(struct tq_xacml_response_s *response) {
    struct tq_xacml_category_s *obligation, *obligation_tmp;
    struct tq_xacml_category_s *advice, *advice_tmp;
    struct tq_xacml_attribute_s *attribute, *attribute_tmp;

    free(response->ns);
    TAILQ_FOREACH_SAFE(obligation, &response->obligations, next, obligation_tmp) {
        TAILQ_REMOVE(&response->obligations, obligation, next);
        delete_normalized_xacml_category(obligation);
        free(obligation);
    }
    TAILQ_FOREACH_SAFE(advice, &response->advices, next, advice_tmp) {
        TAILQ_REMOVE(&response->advices, advice, next);
        delete_normalized_xacml_category(advice);
        free(advice);
    }
    TAILQ_FOREACH_SAFE(attribute, &response->attributes, next, attribute_tmp) {
        TAILQ_REMOVE(&response->attributes, attribute, next);
        delete_normalized_xacml_attribute(attribute);
        free(attribute);
    }
    free(response);
}

void
delete_normalized_xacml_request(struct tq_xacml_request_s *request) {
    struct tq_xacml_category_s *category;
    struct tq_xacml_attribute_s *attribute;
    struct tq_xacml_attribute_value_s *value;
    struct tq_xacml_category_s *category_tmp;
    struct tq_xacml_attribute_s *attribute_tmp;
    struct tq_xacml_attribute_value_s *value_tmp;

    free(request->ns);
    TAILQ_FOREACH_SAFE(category, &request->categories, next, category_tmp) {
        TAILQ_REMOVE(&request->categories, category, next);
        delete_normalized_xacml_category(category);
        free(category);
    }
    memset(request, 0, sizeof(struct tq_xacml_request_s));
    free(request);
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
pdp_xml_input_processor(struct tq_xacml_request_s **xacml_req,
                        evhtp_request_t *evhtp_req) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    size_t bufsize = 0;
    xmlDocPtr  doc;
    xmlNodePtr root_element = NULL;
    unsigned char *buf = NULL;


    syslog(LOG_DEBUG, "%s: %s", __func__, buf);
    LIBXML_TEST_VERSION;

    /* Read document */
    doc = xmlReadMemory(evpull(evhtp_req->buffer_in),
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


static evhtp_res
pdp_policy_evaluation(struct tq_xacml_request_s *xacml_req,
                      struct tq_xacml_response_s **xacml_res) {
    evhtp_res http_res = EVHTP_RES_200;

    if (xacml_req == NULL || xacml_res == NULL) {
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* Construct response */
    *xacml_res = malloc(sizeof(struct tq_xacml_response_s));
    if (*xacml_res == NULL) {
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* Set namespace to XACML 3.0 */
    (*xacml_res)->ns = strdup("urn:oasis:names:tc:xacml:3.0:core:schema:wd-17");
    if ((*xacml_res)->ns == NULL) {
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }
    TAILQ_INIT(&((*xacml_res)->obligations));
    TAILQ_INIT(&((*xacml_res)->advices));
    TAILQ_INIT(&((*xacml_res)->attributes));


    http_res = EVHTP_RES_200;
final:
    return http_res;
}

static evhtp_res
pdp_xml_output_processor(struct evbuffer *output,
                         struct tq_xacml_response_s *xacml_res) {
    evhtp_res http_res = EVHTP_RES_200;

    evbuffer_add_printf(output,
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
"<Response xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 http://docs.oasis-open.org/xacml/3.0/xacml-core-v3-schema-wd-17.xsd\">"
"  <Result>"
"    <Decision>NotApplicable</Decision>"
"  </Result>"
"</Response>");

    return http_res;
}

void
pdp_cb(evhtp_request_t *req, void *arg) {
    evhtp_res                   http_res = EVHTP_RES_SERVERR;
    struct sockaddr_in         *sin;
    /* struct app                 *app; */
    evthr_t                    *thread;
    evhtp_connection_t         *conn;
    struct tq_xacml_request_s  *xacml_req = NULL;
    struct tq_xacml_response_s *xacml_res = NULL;
    char                        tmp[64];

    thread = get_request_thr(req);
    conn   = evhtp_request_get_connection(req);
    /* app    = (struct app *)evthr_get_aux(thread); */
    sin    = (struct sockaddr_in *)conn->saddr;
    evutil_inet_ntop(sin->sin_family, &sin->sin_addr, tmp, sizeof(tmp));

    syslog(LOG_INFO, "PDP: src:ip:%s port:%d", tmp, ntohs(sin->sin_port));

    /* pause the req processing */
    /* evhtp_request_pause(req); */


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


    /* Which output is selected */
    switch (accept_format(req)) {
        case TYPE_APP_XACML_XML:
        case TYPE_APP_ALL:
            syslog(LOG_DEBUG, "pdp xml");
            http_res = pdp_xml_input_processor(&xacml_req, req);
            if (http_res == EVHTP_RES_200) {
                http_res = pdp_policy_evaluation(xacml_req, &xacml_res);
                if (http_res == EVHTP_RES_200) {
                    http_res = pdp_xml_output_processor(req->buffer_out, xacml_res);
                    evhtp_headers_add_header(req->headers_out,
                                             evhtp_header_new("Content-Type",
                                                              "application/xacml+xml; version=3.0", 0, 0));
                }
            }
            goto final;
        default:
            /* syslog: source made a bad request */
            http_res = EVHTP_RES_UNSUPPORTED;
            goto final;
    }

final:
    delete_normalized_xacml_request(xacml_req);
    delete_normalized_xacml_response(xacml_res);
    xacml_req = NULL;
    xacml_res = NULL;

    evhtp_send_reply(req, http_res);
    return;
}
