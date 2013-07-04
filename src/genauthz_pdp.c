#include "ga_config.h"
#include "genauthz/genauthz_pdp.h"

static void
pdp_phase2(struct request_mngr_s *request_mngr,
           evhtp_res http_res) {

    if (!request_mngr)
        goto cleanup;

cleanup:
    evhtp_send_reply(request_mngr->evhtp_req, http_res);
    if (request_mngr->paused == YES) {
        evhtp_request_resume(request_mngr->evhtp_req);
        request_mngr->paused = NO;
    }
    return;
}


static evhtp_res
pdp_input_phase(struct request_mngr_s *request_mngr) {
    evhtp_res                   http_res = EVHTP_RES_SERVERR;

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
                            htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)));
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
                          htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
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
                          htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
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
                                htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
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
                            htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
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
                            htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
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
                            htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
                            request_mngr->accept_header, request_mngr->contenttype_header,
                            http_res);
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* Here the http_res is 200 or within 200 as a statement that all went well so far */

final:
    return http_res;
}

static evhtp_res
pdp_evaluation_phase(struct request_mngr_s *request_mngr) {
    evhtp_res                   http_res = EVHTP_RES_SERVERR;

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
                            htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
                            request_mngr->accept_header, request_mngr->contenttype_header,
                            http_res);
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* Generic - Run policy evaluation */
    http_res = pdp_policy_evaluation(request_mngr);
    if (http_res != EVHTP_RES_200) {
        syslog(LOG_ERR    , "[PDP][pid:%lu][threadid:%lu]"
                            "[src:ip:%s][src:port:%u]"
                            "[method:%s]"
                            "[accept:%s][contenttype:%s]"
                            "[error=%d:Internal service error in policy evaluator]",
                            request_mngr->pid, request_mngr->pthr,
                            request_mngr->sin_ip_addr,request_mngr->sin_port,
                            htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
                            request_mngr->accept_header, request_mngr->contenttype_header,
                            http_res);
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

final:
    return http_res;
}

static evhtp_res
pdp_output_phase(struct request_mngr_s *request_mngr) {
    evhtp_res                   http_res = EVHTP_RES_SERVERR;

    /* Adding the Content-Type header for XML */


    /* Construct response message */
    switch (request_mngr->accept_type) {
        case TYPE_APP_XML:
        case TYPE_APP_XACML_XML:
            evhtp_headers_add_header(request_mngr->evhtp_req->headers_out,
                                     evhtp_header_new(GA_HTTP_HEADER_CONTENT_TYPE,
                                                      GA_HTTP_HEADER_CONTENT_TYPE_XACML_XML_V3, 0, 0));
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
                                    htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
                                    request_mngr->accept_header, request_mngr->contenttype_header,
                                    http_res);
                http_res = EVHTP_RES_SERVERR;
                goto final;
            }
            break;
        case TYPE_APP_JSON:
        case TYPE_APP_XACML_JSON:
            evhtp_headers_add_header(request_mngr->evhtp_req->headers_out,
                                     evhtp_header_new(GA_HTTP_HEADER_CONTENT_TYPE,
                                                      GA_HTTP_HEADER_CONTENT_TYPE_XACML_JSON_V3, 0, 0));
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
                                    htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
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

    syslog(LOG_NOTICE , "[PDP][pid:%lu][threadid:%lu]"
                        "[src:ip:%s][src:port:%u]"
                        "[method:%s]"
                        "[accept:%s][contenttype:%s]"
                        "[httpcode:%d][decision:%s]",
                        request_mngr->pid, request_mngr->pthr,
                        request_mngr->sin_ip_addr,request_mngr->sin_port,
                        htparser_get_methodstr_m(evhtp_request_get_method(request_mngr->evhtp_req)),
                        request_mngr->accept_header, request_mngr->contenttype_header,
                        http_res,
                        xacml_decision2str(request_mngr->xacml_res->decision));

final:
    return http_res;
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

    /* Create a request_mngr object from a request */
    request_mngr = create_request_mngr_from_evhtp_request_with_arg(req, arg, "PDP");
    if (!request_mngr) {
        syslog(LOG_ERR, "[PDP][pid:%lu][threadid:%lu]"
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

   /* Pause the request processing */
   evhtp_request_pause(request_mngr->evhtp_req);
   request_mngr->paused = YES;


    /* Got thread specific data? */
    if (request_mngr->app == NULL) {
        syslog(LOG_ERR, "[PDP][pid:%lu][threadid:%lu]"
                        "[src:ip:%s][src:port:%u]"
                        "[error=no thread specific data accessible]",
                        request_mngr->pid, request_mngr->pthr,
                        request_mngr->sin_ip_addr,request_mngr->sin_port);
        goto final_error_without_reply;
    }

    /* Input */
    http_res = pdp_input_phase(request_mngr);
    if (http_res != EVHTP_RES_200)
        goto final;

    /* Evaluate */
    http_res = pdp_evaluation_phase(request_mngr);
    if (http_res != EVHTP_RES_200)
        goto final;

    /* Output */
    http_res = pdp_output_phase(request_mngr);
    if (http_res != EVHTP_RES_200)
        goto final;

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
    /* evhtp_send_reply(request_mngr->evhtp_req, http_res); */

    /* Seperate reply */
    pdp_phase2(request_mngr, http_res);
    return;


final_error_without_reply:
    /* Continue on error */
    if (request_mngr->paused == YES) {
        evhtp_request_resume(request_mngr->evhtp_req);
        request_mngr->paused = NO;
    }

    /* Clean up memory */
    delete_request_mngr(request_mngr);
    request_mngr = NULL;
    return;
}

