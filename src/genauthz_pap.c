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
#include "genauthz_pap.h"
#include "genauthz_xacml.h"
#include "genauthz_normalized_xacml.h"
#include "genauthz_xacml_rule_parser.h"
#include "genauthz_evaluator.h"
#include "genauthz_xml_xacml.h"
#include "genauthz_json_xacml.h"


void
pap_cb(evhtp_request_t *req, void *arg) {
    evhtp_res                   http_res = EVHTP_RES_SERVERR;
    struct request_mngr_s      *request_mngr;

    /* Prerequisit */
    if (!req || !req->conn) {
        syslog(LOG_ERR, "[PAP][pid:%lu][threadid:%lu]"
                        "[msg=No request object or connection object in request object - problem in evhtp/libevent]",
                         (uint64_t)getpid(),
                         pthread_self()
                        );
        return;
    }

    /* Create a request_mngr object from a request */
    request_mngr = create_request_mngr_from_evhtp_request_with_arg(req, arg, "PAP");
    if (!request_mngr) {
        syslog(LOG_ERR, "[PAP][pid:%lu][threadid:%lu]"
                        "[msg=Error: Failed to create the request_mngr object with request data]",
                         (uint64_t)getpid(),
                         pthread_self()
                        );
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
        syslog(LOG_ERR, "[PAP][pid:%lu][threadid:%lu]"
                        "[src:ip:%s][src:port:%u]"
                        "[error=no thread specific data accessible]",
                        request_mngr->pid, request_mngr->pthr,
                        request_mngr->sin_ip_addr,request_mngr->sin_port);
        goto final_error_without_reply;
    }

    /* Only accept a GET */
    if (request_mngr->evhtp_req->method == htp_method_GET) {
        /* Print policy into output buffer */
        policy_2_evb(request_mngr->evhtp_req->buffer_out,
                     request_mngr->app->parent->xacml_policy);
        http_res = EVHTP_RES_200;

        syslog(LOG_NOTICE , "[PAP][pid:%lu][threadid:%lu]"
                            "[src:ip:%s][src:port:%u]"
                            "[method:%s]"
                            "[accept:%s][contenttype:%s]"
                            "[httpcode:%d][response:status]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
                            request_mngr->accept_header, request_mngr->contenttype_header,
                            http_res);
    } else {
        syslog(LOG_WARNING, "[PAP][pid:%lu][threadid:%lu]"
                            "[src:ip:%s][src:port:%u]"
                            "[accept:%s][contenttype:%s]"
                            "[warning=unexpected HTTP method used][warningvalue:%s]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            request_mngr->accept_header,
                            request_mngr->contenttype_header,
                            htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)));
        http_res = EVHTP_RES_METHNALLOWED;
        goto final;
    }

    /* Done */

final:
    /* Print debug info */
    if (request_mngr->app->parent->debug) {
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


