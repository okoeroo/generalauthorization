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
#include "genauthz_xacml_rule_parser.h"
#include "genauthz_evaluator.h"
#include "genauthz_xml_xacml.h"
#include "genauthz_json_xacml.h"


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
    request_mngr->evhtp_req          = req;
    request_mngr->conn               = req ? evhtp_request_get_connection(req) : NULL;
    request_mngr->sin                = (struct sockaddr_in *)request_mngr->conn->saddr;
    request_mngr->sin_port           = request_mngr->sin ? ntohs(request_mngr->sin->sin_port) : 0;
    request_mngr->evhtp_thr          = request_mngr->evhtp_req ?
                                        get_request_thr(request_mngr->evhtp_req) : NULL;
    request_mngr->service            = request_mngr->evhtp_thr ?
                                        (struct tq_service_s *)evthr_get_aux(request_mngr->evhtp_thr) : NULL;
    request_mngr->listener           = request_mngr->service ?
                                        request_mngr->service->parent_listener : NULL;
    request_mngr->app                = request_mngr->listener ? request_mngr->listener->app_thr : NULL;
    request_mngr->pthr               = pthread_self();
    request_mngr->pid                = (uint64_t)getpid();
    request_mngr->accept_type        = mimetype_normalizer_int(request_mngr->evhtp_req, "Accept");
    request_mngr->accept_header      = mimetype_normalizer_str(request_mngr->accept_type);
    request_mngr->content_type       = mimetype_normalizer_int(request_mngr->evhtp_req, "Content-Type");
    request_mngr->contenttype_header = mimetype_normalizer_str(request_mngr->content_type);
    request_mngr->xacml_req          = NULL;
    request_mngr->xacml_res          = NULL;

    /* Normalizing flawed input for human readable strings */
    if (request_mngr->accept_header == NULL)      request_mngr->accept_header = "<empty Accept>";
    if (request_mngr->contenttype_header == NULL) request_mngr->contenttype_header = "<empty Content-Type>";

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

    /* Update call counter */
    if (request_mngr->app) {
        request_mngr->app->thread_call_count++;
        if (request_mngr->app->parent) request_mngr->app->parent->total_call_count++;
        if (request_mngr->listener) request_mngr->listener->listener_call_count++;
        if (request_mngr->service) request_mngr->service->uri_call_count++;
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
                            "[accept:%s][contenttype:%s]"
                            "[warning=unexpected HTTP method used][warningvalue:%s]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            request_mngr->accept_header,
                            request_mngr->contenttype_header,
                            htparser_get_methodstr_m(req->method));
        http_res = EVHTP_RES_METHNALLOWED;
        goto final;
    }

    /* Test on Accept header */
    if (request_mngr->accept_type == TYPE_APP_UNKNOWN) {
        syslog(LOG_ERR  , "[PDP][pid:%lu][threadid:%lu]"
                          "[src:ip:%s][src:port:%u]"
                          "[method:%s]"
                          "[contenttype:%s]"
                          "[error=unsupported Accept header]",
                          request_mngr->pid, request_mngr->pthr,
                          request_mngr->sin_ip_addr,request_mngr->sin_port,
                          htparser_get_methodstr_m(req->method),
                          request_mngr->contenttype_header);
        http_res = EVHTP_RES_UNSUPPORTED;
        goto final;
    }
    /* Test on Content-Type header */
    if (request_mngr->content_type == TYPE_APP_UNKNOWN) {
        syslog(LOG_ERR  , "[PDP][pid:%lu][threadid:%lu]"
                          "[src:ip:%s][src:port:%u]"
                          "[method:%s]"
                          "[accept:%s]"
                          "[error=unsupported Content-Type]",
                          request_mngr->pid, request_mngr->pthr,
                          request_mngr->sin_ip_addr,request_mngr->sin_port,
                          htparser_get_methodstr_m(req->method),
                          request_mngr->accept_header);
        http_res = EVHTP_RES_UNSUPPORTED;
        goto final;
    }

    /* Parse input per Content-Type specification */
    switch (request_mngr->content_type) {
        case TYPE_APP_XML:
        case TYPE_APP_XACML_XML:
            http_res = pdp_xml_input_processor(&(request_mngr->xacml_req),
                                               request_mngr->evhtp_req);
            break;
        case TYPE_APP_JSON:
        case TYPE_APP_XACML_JSON:
            http_res = pdp_json_input_processor(&(request_mngr->xacml_req),
                                                request_mngr->evhtp_req);
            break;
        default:
            syslog(LOG_WARNING, "[PDP][pid:%lu][threadid:%lu]"
                                "[src:ip:%s][src:port:%u]"
                                "[method:%s]"
                                "[accept:%s][contenttype:%s]"
                                "[error:Unsupported Content-Type]",
                                request_mngr->pid, request_mngr->pthr,
                                request_mngr->sin_ip_addr,request_mngr->sin_port,
                                htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                                request_mngr->accept_header, request_mngr->contenttype_header);
            http_res = EVHTP_RES_UNSUPPORTED;
            goto final;
    }
    /* How did the input parsing go? */
    if (http_res >= 400 && http_res < 500) {
        syslog(LOG_WARNING, "[PDP][pid:%lu][threadid:%lu]"
                            "[src:ip:%s][src:port:%u]"
                            "[method:%s]"
                            "[accept:%s][contenttype:%s]"
                            "[warning=%d:Received request could not be parser and normalized]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                            request_mngr->accept_header, request_mngr->contenttype_header,
                            http_res);
        http_res = EVHTP_RES_UNSUPPORTED;
        goto final;
    } else if (http_res >= 500 && http_res < 600) {
        syslog(LOG_ERR    , "[PDP][pid:%lu][threadid:%lu]"
                            "[src:ip:%s][src:port:%u]"
                            "[method:%s]"
                            "[accept:%s][contenttype:%s]"
                            "[error=%d:Internal service error. Possibly due to a memory allocation failure]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                            request_mngr->accept_header, request_mngr->contenttype_header,
                            http_res);
        http_res = EVHTP_RES_SERVERR;
        goto final;
    } else if (http_res < 200 || http_res >= 300) {
        syslog(LOG_ERR    , "[PDP][pid:%lu][threadid:%lu]"
                            "[src:ip:%s][src:port:%u]"
                            "[method:%s]"
                            "[accept:%s][contenttype:%s]"
                            "[error=%d:Internal service error. I have no idea how this happened]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                            request_mngr->accept_header, request_mngr->contenttype_header,
                            http_res);
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* Here the http_res is 200 or within 200 as a statement that all went well so far */


    /* Generic - Response object */
    request_mngr->xacml_res = create_normalized_xacml_response();
    if (request_mngr->xacml_res == NULL) {
        syslog(LOG_ERR    , "[PDP][pid:%lu][threadid:%lu]"
                            "[src:ip:%s][src:port:%u]"
                            "[method:%s]"
                            "[accept:%s][contenttype:%s]"
                            "[error=%d:Internal service error: out of memory]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                            request_mngr->accept_header, request_mngr->contenttype_header,
                            http_res);
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* Generic - Run policy evaluation */
    http_res = pdp_policy_evaluation(request_mngr->xacml_req,
                                     request_mngr->xacml_res,
                                     request_mngr->app->parent->xacml_policy);
    if (http_res != EVHTP_RES_200) {
        syslog(LOG_ERR    , "[PDP][pid:%lu][threadid:%lu]"
                            "[src:ip:%s][src:port:%u]"
                            "[method:%s]"
                            "[accept:%s][contenttype:%s]"
                            "[error=%d:Internal service error in policy evaluator]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                            request_mngr->accept_header, request_mngr->contenttype_header,
                            http_res);
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* Construct response message */
    switch (request_mngr->accept_type) {
        case TYPE_APP_XML:
        case TYPE_APP_XACML_XML:
            http_res = pdp_xml_output_processor(request_mngr->evhtp_req->buffer_out,
                                                request_mngr->xacml_res);
            if (http_res != EVHTP_RES_200) {
                syslog(LOG_ERR    , "[PDP][pid:%lu][threadid:%lu]"
                                    "[src:ip:%s][src:port:%u]"
                                    "[method:%s]"
                                    "[accept:%s][contenttype:%s]"
                                    "[error=%d:Internal service error in XML output assembly]",
                                    request_mngr->pid, request_mngr->pthr,
                                    request_mngr->sin_ip_addr,request_mngr->sin_port,
                                    htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                                    request_mngr->accept_header, request_mngr->contenttype_header,
                                    http_res);
                http_res = EVHTP_RES_SERVERR;
                goto final;
            }
            break;
        case TYPE_APP_JSON:
        case TYPE_APP_XACML_JSON:
            http_res = pdp_json_output_processor(request_mngr->evhtp_req->buffer_out,
                                                 request_mngr->xacml_res);
            if (http_res != EVHTP_RES_200) {
                syslog(LOG_ERR    , "[PDP][pid:%lu][threadid:%lu]"
                                    "[src:ip:%s][src:port:%u]"
                                    "[method:%s]"
                                    "[accept:%s][contenttype:%s]"
                                    "[error=%d:Internal service error in JSON output assembly]",
                                    request_mngr->pid, request_mngr->pthr,
                                    request_mngr->sin_ip_addr,request_mngr->sin_port,
                                    htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                                    request_mngr->accept_header, request_mngr->contenttype_header,
                                    http_res);
                http_res = EVHTP_RES_SERVERR;
                goto final;
            }
            break;
        default:
            http_res = EVHTP_RES_UNSUPPORTED;
            goto final;
    }

    /* Adding the Content-Type header for XML */
    evhtp_headers_add_header(request_mngr->evhtp_req->headers_out,
                             evhtp_header_new("Content-Type",
                                              "application/xacml+xml; version=3.0", 0, 0));

    syslog(LOG_NOTICE , "[PDP][pid:%lu][threadid:%lu]"
                        "[src:ip:%s][src:port:%u]"
                        "[method:%s]"
                        "[accept:%s][contenttype:%s]"
                        "[httpcode:%d][decision:%s]",
                        request_mngr->pid, request_mngr->pthr,
                        request_mngr->sin_ip_addr,request_mngr->sin_port,
                        htparser_get_methodstr_m(request_mngr->evhtp_req->method),
                        request_mngr->accept_header, request_mngr->contenttype_header,
                        http_res,
                        xacml_decision2str(request_mngr->xacml_res->decision));
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

