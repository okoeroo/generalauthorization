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


static evhtp_res
pdp_xml_processor(evhtp_request_t *req) {
    evhtp_res http_res = EVHTP_RES_SERVERR;

    printf("%s\n", __func__);

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
        goto bad_request;
    }
    printf("%s\n", __func__);


    /* Which output is selected */
    switch (accept_format(req)) {
        case TYPE_APP_XACML_XML:
        case TYPE_APP_ALL:
            printf("pdp xml\n");
            http_res = pdp_xml_processor(req);
            break;
        default:
            /* syslog: source made a bad request */
            printf("Bad Accept: \n");
            goto bad_request;
    }

    /* All ok */
    evhtp_send_reply(req, http_res);
    return;

bad_request:
    http_res = EVHTP_RES_BADREQ;
    evhtp_send_reply(req, http_res);
    return;
}
