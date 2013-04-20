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

static evhtp_res
pdp_xml_processor(evhtp_request_t *req) {
    evhtp_res http_res = EVHTP_RES_SERVERR;

    syslog(LOG_DEBUG, "%s", __func__);

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
