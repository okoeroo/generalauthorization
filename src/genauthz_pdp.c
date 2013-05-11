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
                         (uint64_t)getpid(),
                         pthread_self()
                        );
        return;
    }

    /* Request administration object */
    request_mngr = calloc(sizeof(struct request_mngr_s), 1);
    if (request_mngr == NULL) {
        syslog(LOG_ERR, "[PDP][pid:%lu][threadid:%lu]"
                        "[msg=Error: out of memory]",
                         (uint64_t)getpid(),
                         pthread_self()
                        );
        return;
    }

    /* request administration */
    request_mngr->evhtp_req = req;
    request_mngr->conn      = req ?
                                    evhtp_request_get_connection(req) : NULL;
    request_mngr->sin       = (struct sockaddr_in *)request_mngr->conn->saddr;
    request_mngr->sin_port  = request_mngr->sin ?
                                    ntohs(request_mngr->sin->sin_port) : 0;
    request_mngr->evhtp_thr = request_mngr->evhtp_req ?
                                    get_request_thr(request_mngr->evhtp_req) : NULL;
    request_mngr->listener  = request_mngr->evhtp_thr ?
                                    (struct tq_listener_s *)evthr_get_aux(request_mngr->evhtp_thr) : NULL;
    request_mngr->app       = request_mngr->listener ?
                                    request_mngr->listener->app_thr : NULL;
    request_mngr->pthr      = pthread_self();
    request_mngr->pid       = (uint64_t)getpid();
    request_mngr->appaccept = 0;
    request_mngr->xacml_req = NULL;
    request_mngr->xacml_res = NULL;

    /* Copy the IP address */
    request_mngr->sin_ip_addr = calloc(IP_ADDRESS_LEN, 1);
    if (request_mngr->sin_ip_addr == NULL) {
        syslog(LOG_ERR, "[PDP][pid:%lu][threadid:%lu]"
                        "[error=out of memory]",
                         request_mngr->pid, request_mngr->pthr);
        goto final_error_without_reply;
    }

    evutil_inet_ntop(request_mngr->sin->sin_family,
                     &request_mngr->sin->sin_addr,
                     request_mngr->sin_ip_addr,
                     IP_ADDRESS_LEN);
    if (!req) {
        syslog(LOG_ERR, "[PDP][pid:%lu][threadid:%lu]"
                        "[error=evutil_inet_ntop() failed]",
                        request_mngr->pid, request_mngr->pthr);
        goto final_error_without_reply;
    }

    /* Got thread specific data? */
    if (request_mngr->app == NULL) {
        syslog(LOG_ERR, "[PDP][pid:%lu][threadid:%lu]"
                        "[src:ip:%s][src:port:%u]"
                        "[error=no thread specific data accessible]",
                        request_mngr->pid, request_mngr->pthr,
                         request_mngr->sin_ip_addr,request_mngr->sin_port);
        goto final_error_without_reply;
    }

    /* Only accept a POST */
    if (request_mngr->evhtp_req->method != htp_method_POST) {
        syslog(LOG_WARNING, "[PDP][pid:%lu][threadid:%lu]"
                            "[src:ip:%s][src:port:%u]"
                            "[method:%s]"
                            "[error=unexpected HTTP method used]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            htparser_get_methodstr_m(req->method));
        http_res = EVHTP_RES_METHNALLOWED;
        goto final;
    }

    /* Which output is selected */
    request_mngr->appaccept = accept_format(request_mngr->evhtp_req);
    switch (request_mngr->appaccept) {
        case TYPE_APP_XML:
            syslog(LOG_DEBUG, "[PDP][pid:%lu][threadid:%lu]"
                              "[src:ip:%s][src:port:%u]"
                              "[method:%s][accept:application/xml]"
                              "[msg=Received request]",
                              request_mngr->pid, request_mngr->pthr,
                              request_mngr->sin_ip_addr,request_mngr->sin_port,
                              htparser_get_methodstr_m(request_mngr->evhtp_req->method));
            break;
        case TYPE_APP_XACML_XML:
            syslog(LOG_DEBUG, "[PDP][pid:%lu][threadid:%lu]"
                              "[src:ip:%s][src:port:%u]"
                              "[method:%s][accept:application/xacml+xml]"
                              "[msg=Received request]",
                              request_mngr->pid, request_mngr->pthr,
                              request_mngr->sin_ip_addr,request_mngr->sin_port,
                              htparser_get_methodstr_m(request_mngr->evhtp_req->method));
            break;
        case TYPE_APP_JSON:
            syslog(LOG_DEBUG, "[PDP][pid:%lu][threadid:%lu]"
                              "[src:ip:%s][src:port:%u]"
                              "[method:%s][accept:application/json]"
                              "[msg=Received request]",
                              request_mngr->pid, request_mngr->pthr,
                              request_mngr->sin_ip_addr,request_mngr->sin_port,
                              htparser_get_methodstr_m(request_mngr->evhtp_req->method));
            break;
        case TYPE_APP_XACML_JSON:
            syslog(LOG_DEBUG, "[PDP][pid:%lu][threadid:%lu]"
                              "[src:ip:%s][src:port:%u]"
                              "[method:%s][accept:application/xacml+json]"
                              "[msg=Received request]",
                              request_mngr->pid, request_mngr->pthr,
                              request_mngr->sin_ip_addr,request_mngr->sin_port,
                              htparser_get_methodstr_m(request_mngr->evhtp_req->method));
            break;
        case TYPE_APP_ALL:
            syslog(LOG_DEBUG, "[PDP][pid:%lu][threadid:%lu]"
                              "[src:ip:%s][src:port:%u]"
                              "[method:%s][accept:*/*]"
                              "[msg=Received request]",
                              request_mngr->pid, request_mngr->pthr,
                              request_mngr->sin_ip_addr,request_mngr->sin_port,
                              htparser_get_methodstr_m(request_mngr->evhtp_req->method));
        default:
            syslog(LOG_ERR  , "[PDP][pid:%lu][threadid:%lu]"
                              "[src:ip:%s][src:port:%u]"
                              "[method:%s]"
                              "[error=unsupported media type][errorvalue=%.32s]",
                              request_mngr->pid, request_mngr->pthr,
                              request_mngr->sin_ip_addr,request_mngr->sin_port,
                              htparser_get_methodstr_m(req->method),
                              evhtp_header_find(req->headers_in, "accept") ?
                                  evhtp_header_find(req->headers_in, "accept") :
                                  "no accept");
            http_res = EVHTP_RES_UNSUPPORTED;
            goto final;
    }


/* Error/info/warning handling */

    switch (request_mngr->appaccept) {
        case TYPE_APP_XML:
        case TYPE_APP_XACML_XML:
            http_res = pdp_xml_input_processor(&(request_mngr->xacml_req),
                                               request_mngr->evhtp_req);
            if (http_res >= 400 && http_res < 500) {
                syslog(LOG_WARNING, "[PDP][pid:%lu][threadid:%lu]"
                                    "[src:ip:%s][src:port:%u]"
                                    "[method:%s][JSON]"
                                    "[error=%d:Received request could not be parser and normalized]",
                                    request_mngr->pid, request_mngr->pthr,
                                    request_mngr->sin_ip_addr,request_mngr->sin_port,
                                    htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                                    http_res);
                http_res = EVHTP_RES_UNSUPPORTED;
                goto final;
            } else if (http_res >= 500 && http_res < 600) {
                syslog(LOG_ERR    , "[PDP][pid:%lu][threadid:%lu]"
                                    "[src:ip:%s][src:port:%u]"
                                    "[method:%s][JSON]"
                                    "[error=%d:Internal service error. Possibly due to a memory allocation failure]",
                                    request_mngr->pid, request_mngr->pthr,
                                    request_mngr->sin_ip_addr,request_mngr->sin_port,
                                    htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                                    http_res);
                http_res = EVHTP_RES_SERVERR;
                goto final;
            } else if (http_res < 200 || http_res >= 300) {
                syslog(LOG_ERR    , "[PDP][pid:%lu][threadid:%lu]"
                                    "[src:ip:%s][src:port:%u]"
                                    "[method:%s][JSON]"
                                    "[error=%d:Internal service error. I have no idea how this happened]",
                                    request_mngr->pid, request_mngr->pthr,
                                    request_mngr->sin_ip_addr,request_mngr->sin_port,
                                    htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                                    http_res);
                http_res = EVHTP_RES_SERVERR;
                goto final;
            }
        case TYPE_APP_JSON:
        case TYPE_APP_XACML_JSON:
            http_res = EVHTP_RES_UNSUPPORTED;
            goto final;
        default:
            http_res = EVHTP_RES_UNSUPPORTED;
            goto final;
    }


    /* http_res is or within 200 */
    request_mngr->xacml_res = create_normalized_xacml_response();
    http_res = pdp_policy_evaluation(request_mngr->xacml_req,
                                     request_mngr->xacml_res,
                                     request_mngr->app->parent->xacml_policy);
    if (http_res != EVHTP_RES_200) {
        syslog(LOG_ERR    , "[PDP][pid:%lu][threadid:%lu]"
                            "[src:ip:%s][src:port:%u]"
                            "[method:%s][JSON]"
                            "[error=%d:Internal service error in policy evaluator]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                            http_res);
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    http_res = pdp_xml_output_processor(request_mngr->evhtp_req->buffer_out,
                                        request_mngr->xacml_res);
    if (http_res != EVHTP_RES_200) {
        syslog(LOG_ERR    , "[PDP][pid:%lu][threadid:%lu]"
                            "[src:ip:%s][src:port:%u]"
                            "[method:%s][JSON]"
                            "[error=%d:Internal service error in output assembly]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                            http_res);
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* Adding the Content-Type header for XML */
    evhtp_headers_add_header(request_mngr->evhtp_req->headers_out,
                             evhtp_header_new("Content-Type",
                                              "application/xacml+xml; version=3.0", 0, 0));
    /* Done */

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

