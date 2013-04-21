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
        walk_ns(cur_node->nsDef);
        walk_ns(cur_node->ns);

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

static evhtp_res
pdp_xml_processor(evhtp_request_t *req) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    unsigned char *buf = NULL;
    size_t bufsize = 0;
    xmlDocPtr  doc;
    xmlNodePtr root_element = NULL;

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

    /* Walk child */
    walk(root_element, 0);
    http_res = EVHTP_RES_200;

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
