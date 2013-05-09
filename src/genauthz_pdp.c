#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
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
#include "genauthz_xacml_rule_parser.h"
#include "genauthz_evaluator.h"

#define IP_ADDRESS_LEN 64

static void
delete_request_mngr(struct request_mngr_s *request_mngr) {
    delete_normalized_xacml_request(request_mngr->xacml_req);
    delete_normalized_xacml_response(request_mngr->xacml_res);

    free(request_mngr->sin_ip_addr);
    free(request_mngr);
    return;
}

void
pdp_cb(evhtp_request_t *req, void *arg) {
    evhtp_res                   http_res = EVHTP_RES_SERVERR;
    struct request_mngr_s      *request_mngr;

    /* Prerequisit */
    if (!req || !req->conn) {
        syslog(LOG_ERR, "[PDP][pid:%lu][threadid:%lu]"
                        "[msg=No request object or connection object in request object - problem in evhtp/libevent]",
                         getpid(),
                         pthread_self()
                        );
        return;
    }

    /* Request administration object */
    request_mngr = calloc(sizeof(struct request_mngr_s), 1);
    if (request_mngr == NULL) {
        syslog(LOG_ERR, "[PDP][pid:%lu][threadid:%lu]"
                        "[msg=Error: out of memory]",
                         getpid(),
                         pthread_self()
                        );
        return;
    }

    /* request administration */
    request_mngr->evhtp_req = req;
    request_mngr->conn      = req ? evhtp_request_get_connection(req) : NULL;
    request_mngr->sin       = (struct sockaddr_in *)request_mngr->conn->saddr;
    request_mngr->sin_port  = request_mngr->sin ? ntohs(request_mngr->sin->sin_port) : 0;
    request_mngr->evhtp_thr = request_mngr->evhtp_req ? get_request_thr(request_mngr->evhtp_req) : NULL;
    request_mngr->app       = request_mngr->evhtp_thr ? (struct app *)evthr_get_aux(request_mngr->evhtp_thr) : NULL;
    request_mngr->pthr      = pthread_self();
    request_mngr->pid       = getpid();
    request_mngr->xacml_req = NULL;
    request_mngr->xacml_res = NULL;

    /* Copy the IP address */
    request_mngr->sin_ip_addr = calloc(IP_ADDRESS_LEN, 1);
    if (request_mngr->sin_ip_addr == NULL) {
        syslog(LOG_ERR, "[PDP][pid:%lu][threadid:%lu]"
                        "[msg=Error: out of memory]",
                         request_mngr->pid, request_mngr->pthr);
        goto final_error_without_reply;
    }

    evutil_inet_ntop(request_mngr->sin->sin_family,
                     &request_mngr->sin->sin_addr,
                     request_mngr->sin_ip_addr,
                     IP_ADDRESS_LEN);
    if (!req) {
        syslog(LOG_ERR, "[PDP][pid:%lu][threadid:%lu]"
                        "[msg=evutil_inet_ntop() failed]",
                         request_mngr->pid, request_mngr->pthr);
        goto final_error_without_reply;
    }

    /* Got thread specific data? */
    if (request_mngr->app == NULL) {
        syslog(LOG_ERR, "[PDP][pid:%lu][threadid:%lu]"
                        "[src:ip:%s][src:port:%u]"
                        "[msg=Error: no thread specific data accessible]",
                         request_mngr->pid, request_mngr->pthr,
                         request_mngr->sin_ip_addr,request_mngr->sin_port);
        goto final_error_without_reply;
    }

    /* Only accept a POST */
    if (request_mngr->evhtp_req->method != htp_method_POST) {
        syslog(LOG_WARNING, "[PDP][pid:%lu][threadid:%lu]"
                            "[src:ip:%s][src:port:%u]"
                            "[method:%s]"
                            "[msg=Error: unexpected HTTP method used]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            htparser_get_methodstr_m(req->method));
        http_res = EVHTP_RES_METHNALLOWED;
        goto final;
    }

    /* Which output is selected */
    switch (accept_format(request_mngr->evhtp_req)) {
        case TYPE_APP_ALL:
        case TYPE_APP_XACML_XML:
            syslog(LOG_INFO, "[PDP][XML][pid:%lu][threadid:%lu]"
                             "[src:ip:%s][src:port:%u]"
                             "[method:%s]",
                             request_mngr->pid, request_mngr->pthr,
                             request_mngr->sin_ip_addr,request_mngr->sin_port,
                             htparser_get_methodstr_m(request_mngr->evhtp_req->method));
            http_res = pdp_xml_input_processor(&(request_mngr->xacml_req),
                                               request_mngr->evhtp_req);

            if (http_res == EVHTP_RES_200) {
                request_mngr->xacml_res = create_normalized_xacml_response();
                http_res = pdp_policy_evaluation(request_mngr->xacml_req,
                                                 request_mngr->xacml_res,
                                                 request_mngr->app->parent->xacml_policy);
                if (http_res == EVHTP_RES_200) {
                    http_res = pdp_xml_output_processor(request_mngr->evhtp_req->buffer_out,
                                                        request_mngr->xacml_res);
                    evhtp_headers_add_header(request_mngr->evhtp_req->headers_out,
                                             evhtp_header_new("Content-Type",
                                                              "application/xacml+xml; version=3.0", 0, 0));
                }
            }
            goto final;
        case TYPE_APP_JSON:
        case TYPE_APP_XACML_JSON:
        default:
            /* syslog: source made a bad request */
            http_res = EVHTP_RES_UNSUPPORTED;
            goto final;
    }

final:
    /* Print debug info */
    if (request_mngr->app->parent->debug) {
        /* Print the normalized XACML Request & Response */
        print_normalized_xacml_request(request_mngr->xacml_req);
        print_normalized_xacml_response(request_mngr->xacml_res);
        print_loaded_policy(request_mngr->app->parent->xacml_policy);

        /* Knock out the event loops */
        event_base_loopexit(request_mngr->app->parent->evbase, NULL);
        event_base_loopexit(request_mngr->app->evbase, NULL);
    }
    /* Send reply */
    evhtp_send_reply(request_mngr->evhtp_req, http_res);
final_error_without_reply:
    /* Clean up memory */
    delete_request_mngr(request_mngr);
    request_mngr = NULL;
    return;
}

