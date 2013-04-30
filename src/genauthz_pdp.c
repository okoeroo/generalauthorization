#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_pdp.h"
#include "genauthz_xacml.h"
#include "genauthz_normalized_xacml.h"
#include "genauthz_xml_xacml.h"


void
pdp_cb(evhtp_request_t *req, void *arg) {
    evhtp_res                   http_res = EVHTP_RES_SERVERR;
    struct sockaddr_in         *sin;
    struct app                 *app;
    evthr_t                    *thread;
    evhtp_connection_t         *conn;
    struct tq_xacml_request_s  *xacml_req = NULL;
    struct tq_xacml_response_s *xacml_res = NULL;
    char                        tmp[64];

    thread = get_request_thr(req);
    conn   = evhtp_request_get_connection(req);
    app    = (struct app *)evthr_get_aux(thread);
    sin    = (struct sockaddr_in *)conn->saddr;

    evutil_inet_ntop(sin->sin_family, &sin->sin_addr, tmp, sizeof(tmp));
    if (app == NULL) {
        evhtp_send_reply(req, EVHTP_RES_SERVERR);
        return;
    }

    syslog(LOG_INFO, "PDP: src:ip:%s port:%d", tmp, ntohs(sin->sin_port));
    syslog(LOG_DEBUG, "PDP: thread no. %u", (unsigned int)pthread_self());

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
                xacml_res = create_normalized_xacml_response();
                http_res = pdp_policy_evaluation(xacml_req,
                                                 xacml_res,
                                                 app->parent->xacml_policy);
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
