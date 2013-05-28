#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <evhtp.h>

#include <inttypes.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_control.h"
#include "genauthz_xacml.h"
#include "genauthz_normalized_xacml.h"
#include "genauthz_xacml_rule_parser.h"

#include "generalauthorization.h"


static evhtp_res
control_status_counters(struct request_mngr_s *request_mngr) {
    evhtp_res                   http_res = EVHTP_RES_SERVERR;
    struct tq_listener_s       *listener;
    struct tq_service_s        *service;
    struct tq_xacml_rule_s     *rule;
    unsigned int li, si, ri;

    /* Response header */
    evbuffer_add_printf(request_mngr->evhtp_req->buffer_out,
            "= %s =\n", PACKAGE_STRING);

    evbuffer_add_printf(request_mngr->evhtp_req->buffer_out,
            "- Per interface stats -\n");

    li = 0;
    TAILQ_FOREACH(listener, &(request_mngr->app->parent->listener_head), next) {
        li++;
        evbuffer_add_printf(request_mngr->evhtp_req->buffer_out,
                "%3d Bound to IP        :   %s\n"
                "    Port               :   %d\n"
                "    Backlog            :   %u\n"
                "    Listener hit count :   %" PRIu64 "\n"
                ,
                li,
                listener->bindip,
                listener->port,
                listener->backlog,
                listener->listener_call_count);
        si = 0;
        TAILQ_FOREACH(service, &(listener->services_head), next) {
            evbuffer_add_printf(request_mngr->evhtp_req->buffer_out,
                    "    %3d URI            :   %s\n"
                    "        Thread count   :   %d\n"
                    "        URI hit count  :   %" PRIu64 "\n"
                    ,
                    si,
                    service->uri,
                    service->thread_cnt,
                    service->uri_call_count);
        }
    }
    if (!request_mngr->app->parent->xacml_policy) {
        evbuffer_add_printf(request_mngr->evhtp_req->buffer_out,
                "Error: No XACML policy loaded.\n");
        goto final;
    }

    evbuffer_add_printf(request_mngr->evhtp_req->buffer_out,
            "- Per XACML policy rule stats -\n");
    ri = 0;
    TAILQ_FOREACH(rule, &(request_mngr->app->parent->xacml_policy->xacml_rule_list), next) {
        ri++;
        evbuffer_add_printf(request_mngr->evhtp_req->buffer_out,
                "%3d Rule name          :   %s\n"
                "    Rule hit count     :   %" PRIu64 "\n"
                ,
                ri,
                rule->name,
                rule->rule_call_count);
    }

    http_res = EVHTP_RES_200;
final:
    return http_res;

}

void
control_cb(evhtp_request_t *req, void *arg) {
    evhtp_res                   http_res = EVHTP_RES_SERVERR;
    struct request_mngr_s      *request_mngr;

    /* Prerequisit */
    if (!req || !req->conn) {
        syslog(LOG_ERR, "[CONTROL][pid:%lu][threadid:%lu]"
                        "[msg=No request object or connection object in request object - problem in evhtp/libevent]",
                         (uint64_t)getpid(),
                         pthread_self()
                        );
        return;
    }

    /* Request administration object */
    request_mngr = calloc(sizeof(struct request_mngr_s), 1);
    if (request_mngr == NULL) {
        syslog(LOG_ERR, "[CONTROL][pid:%lu][threadid:%lu]"
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
    request_mngr->service            = arg ? (struct tq_service_s *)arg : NULL;
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
        syslog(LOG_ERR, "[CONTROL][pid:%lu][threadid:%lu]"
                        "[error=out of memory]",
                         request_mngr->pid, request_mngr->pthr);
        goto final_error_without_reply;
    }

    evutil_inet_ntop(request_mngr->sin->sin_family,
                     &request_mngr->sin->sin_addr,
                     request_mngr->sin_ip_addr,
                     IP_ADDRESS_LEN);
    if (!req) {
        syslog(LOG_ERR, "[CONTROL][pid:%lu][threadid:%lu]"
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
        syslog(LOG_ERR, "[CONTROL][pid:%lu][threadid:%lu]"
                        "[src:ip:%s][src:port:%u]"
                        "[error=no thread specific data accessible]",
                        request_mngr->pid, request_mngr->pthr,
                        request_mngr->sin_ip_addr,request_mngr->sin_port);
        goto final_error_without_reply;
    }

    /* Only accept a GET */
    if (request_mngr->evhtp_req->method != htp_method_GET) {
        syslog(LOG_WARNING, "[CONTROL][pid:%lu][threadid:%lu]"
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


    /* Retrieve status counters */
    http_res = control_status_counters(request_mngr);

    syslog(LOG_NOTICE , "[CONTROL][pid:%lu][threadid:%lu]"
                        "[src:ip:%s][src:port:%u]"
                        "[method:%s]"
                        "[accept:%s][contenttype:%s]"
                        "[httpcode:%d][response:status]",
                        request_mngr->pid, request_mngr->pthr,
                        request_mngr->sin_ip_addr,request_mngr->sin_port,
                        htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
                        request_mngr->accept_header, request_mngr->contenttype_header,
                        http_res);
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

