#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <syslog.h>
#include <stdio.h>
#include <evhtp.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

#include "genauthz_xacml.h"
#include "genauthz_common.h"
#include "genauthz_pap.h"
#include "genauthz_pdp.h"
#include "genauthz_control.h"
#include "genauthz_normalized_xacml.h"

#include "genauthz_httprest.h"


#include <sys/types.h>
#include <unistd.h>

static void
app_init_thread(evhtp_t *htp, evthr_t *thread, void *arg) {
    struct tq_listener_s *listener;
    struct tq_service_s *service;
    struct app        *app;

    service     = (struct tq_service_s *)arg;
    listener    = service->parent_listener;
    app         = calloc(sizeof(struct app), 1); /* Also resets thread_call_count */

    app->parent = listener->app_parent;
    app->evbase = evthr_get_base(thread);
    app->evhtp  = htp;

    listener->app_thr = app;

    app->thread_number = app->parent->threads_online;
    app->parent->threads_online++;

    evthr_set_aux(thread, service);
}

evthr_t *
get_request_thr(evhtp_request_t * request) {
    evhtp_connection_t * htpconn;
    evthr_t            * thread;

    htpconn = evhtp_request_get_connection(request);
    thread  = htpconn->thread;

    return thread;
}

void
delete_request_mngr(struct request_mngr_s *request_mngr) {
    delete_normalized_xacml_request(request_mngr->xacml_req);
    delete_normalized_xacml_response(request_mngr->xacml_res);

    free(request_mngr->sin_ip_addr);
    free(request_mngr);
    return;
}

const char *
mimetype_normalizer_str(int accept_header_int) {
    /* Search the HTTP headers for the 'accept:' tag */
    switch (accept_header_int) {
        case TYPE_APP_JSON:             return "application/json";
        case TYPE_APP_XACML_JSON:       return "application/xacml+json";
        case TYPE_APP_XML:              return "application/xml";
        case TYPE_APP_XACML_XML:        return "application/xacml+xml";
        case TYPE_APP_ALL:              return "*/*";
        default:                        return NULL;
    }
    return NULL;
}

int
mimetype_normalizer_int(evhtp_request_t *req, const char *header) {
    const char * accept_h = NULL;

    /* Search the HTTP headers for the 'accept:' tag */
    if ((accept_h = evhtp_header_find(req->headers_in, header))) {
        if (strncmp("application/json", accept_h, strlen("application/json")) == 0) {
            return TYPE_APP_JSON;
        } else if (strncmp("application/xml", accept_h, strlen("application/xml")) == 0) {
            return TYPE_APP_XML;
        } else if (strncmp("application/xacml+xml", accept_h, strlen("application/xacml+xml")) == 0) {
            return TYPE_APP_XACML_XML;
        } else if (strncmp("application/xacml+json", accept_h, strlen("application/xacml+json")) == 0) {
            return TYPE_APP_XACML_JSON;
        } else {
            return TYPE_APP_UNKNOWN;
        }
    }
    /* The default answer is *//* */
    return TYPE_APP_UNKNOWN;
}


static void
generic_http_cb(evhtp_request_t * req, void * a) {
    evhtp_res        http_res  = EVHTP_RES_SERVERR;

    if (!req) {
        syslog(LOG_ERR, "No request object! - problem in evhtp/libevent\n");
        return;
    }
    if (!req->conn) {
        syslog(LOG_ERR, "No connection object in request object - problem in evhtp/libevent\n");
        return;
    }
    syslog(LOG_DEBUG, "%s, %s an argument", __func__, a ? "with" : "without");

    /* All ok */
    http_res = EVHTP_RES_OK;
    evhtp_send_reply(req, http_res);
    return;
}


/* Functions */
int
genauthz_httprest_init(evbase_t * evbase, struct app_parent *app_p) {
    struct passwd *pwd = NULL;
    struct tq_listener_s *p_listener, *tmp_p_listener;
    struct tq_service_s *p_service, *tmp_p_service;

    if (evbase == NULL || app_p == NULL)
        return GA_BAD;

    /* Reset Application parent counter */
    app_p->total_call_count = 0;
    app_p->threads_online   = 0;

    for (p_listener = TAILQ_FIRST(&(app_p->listener_head));
         p_listener != NULL;
         tmp_p_listener = TAILQ_NEXT(p_listener, next),
                p_listener = tmp_p_listener) {

        p_listener->listener_call_count = 0; /* Reset counter */

        p_listener->evhtp = evhtp_new(evbase, NULL);
        if (p_listener->evhtp == NULL) {
            syslog(LOG_ERR, "Failed on evhtp_new()");
            goto cleanup;
        }

        /* Map the Application parent object to each listener */
        p_listener->app_parent = app_p;

        /* Setup security context */
        if (p_listener->scfg) {
            evhtp_ssl_init(p_listener->evhtp, p_listener->scfg);
        }

        /* Bind */
        if (evhtp_bind_socket(p_listener->evhtp, p_listener->bindip,
                              p_listener->port, p_listener->backlog) != 0) {
            syslog(LOG_ERR, "Failed to bind a listener to \"%s\" on port \'%d\'",
                            p_listener->bindip, p_listener->port);
            goto cleanup;
        } else {
            syslog(LOG_INFO, "Listening on \"%s\" on port \'%d\'",
                            p_listener->bindip, p_listener->port);
        }

#if 0
        /* Register thread handler */
        evhtp_use_threads(p_listener->evhtp,
                          app_init_thread,
                          p_listener->thread_cnt,
                          p_listener);
#endif

        for (p_service = TAILQ_FIRST(&(p_listener->services_head));
             p_service != NULL;
             tmp_p_service = TAILQ_NEXT(p_service, next),
                    p_service = tmp_p_service) {

            syslog(LOG_ERR, "URI: \"%s\"", p_service->uri);

            /* Register thread handler */
            evhtp_use_threads(p_listener->evhtp,
                              app_init_thread,
                              p_service->thread_cnt,
                              p_service);

            /* Reset service counter */
            p_service->uri_call_count = 0;

            /* Service type switcher */
            switch(p_service->ltype) {
                case PAP:
                    if (evhtp_set_cb(p_listener->evhtp,
                                     p_service->uri,
                                     pap_cb,
                                     p_service) == NULL) {
                        syslog(LOG_ERR, "Failed to set the PAP callback for the URI \"%s\"", p_service->uri);
                        goto cleanup;
                    } else {
                        syslog(LOG_INFO, "Set the \"PAP\" callback on the URI \"%s\" with \'%d\' threads",
                                         p_service->uri, p_service->thread_cnt);
                    }
                    break;
                case PDP:
                    if (evhtp_set_cb(p_listener->evhtp,
                                     p_service->uri,
                                     pdp_cb,
                                     p_service) == NULL) {
                        syslog(LOG_ERR, "Failed to set the PDP callback for the URI \"%s\"", p_service->uri);
                        goto cleanup;
                    } else {
                        syslog(LOG_INFO, "Set the \"PDP\" callback on the URI \"%s\" with \'%d\' threads",
                                         p_service->uri, p_service->thread_cnt);
                    }
                    break;
                case CONTROL:
                    if (evhtp_set_cb(p_listener->evhtp,
                                     p_service->uri,
                                     control_cb,
                                     p_service) == NULL) {
                        syslog(LOG_ERR, "Failed to set the CONTROL callback for the URI \"%s\"", p_service->uri);
                        goto cleanup;
                    } else {
                        syslog(LOG_INFO, "Set the \"CONTROL\" callback on the URI \"%s\" with \'%d\' threads",
                                         p_service->uri, p_service->thread_cnt);
                    }
                    break;
                default:
                    if (evhtp_set_cb(p_listener->evhtp,
                                     p_service->uri,
                                     generic_http_cb,
                                     p_service) == NULL) {
                        syslog(LOG_ERR, "Failed to set the generic callback for the URI \"%s\"", p_service->uri);
                        goto cleanup;
                    } else {
                        syslog(LOG_INFO, "Set the \"generic_http_cb()\" callback on the URI \"%s\" with \'%d\' threads",
                                         p_service->uri, p_service->thread_cnt);
                    }
                    break;
            }
        }
    }

    /* Privilege downgrade */
    if (geteuid() == 0) {
        /* Test for effective seteuid()-only, like sudo, switch to caller ID */
        if (getuid() != 0) {
            if (getegid() == 0) {
                if (setegid(getgid()) < 0) {
                    return GA_BAD;
                }
            }
            if (seteuid(getuid()) < 0) {
                return GA_BAD;
            }
        } else {
            /* Lower privs after bind to 'okoeroo' or 'nobody' */
            pwd = getpwnam("nobody");
            if (pwd == NULL) {
                return GA_BAD;
            }
            if (getegid() == 0) {
                if (setegid(pwd->pw_gid) < 0)
                    return GA_BAD;
                if (setgid(pwd->pw_gid) < 0)
                    return GA_BAD;
            }
            if (setuid(pwd->pw_uid) < 0)
                return GA_BAD;
            if (seteuid(pwd->pw_uid) < 0)
                return GA_BAD;
        }
    }
    syslog(LOG_DEBUG, "Running as uid: %d, euid: %d, gid: %d, egid: %d", getuid(), geteuid(), getgid(), geteuid());

    return GA_GOOD;
cleanup:
    return GA_BAD;
}

#if 0
    /* Initialize SSL parameters */
    memset(&scfg, 0, sizeof(evhtp_ssl_cfg_t));
    scfg.pemfile            = cert;
    scfg.privfile           = key;
    scfg.cafile             = cafile;
    scfg.capath             = capath;
    scfg.ciphers            = "ALL:!ADH:!LOW:!EXP:@STRENGTH";
    scfg.ssl_opts           = SSL_OP_NO_SSLv2;
    scfg.verify_peer        = SSL_VERIFY_NONE;
    scfg.verify_depth       = 42;
    scfg.scache_type        = evhtp_ssl_scache_type_internal;
    scfg.scache_size        = 1024;
    scfg.scache_timeout     = 1024;

    }

    /* Initializers */
    if (genauthz_state_init_bots() != 0) {
        syslog(LOG_ERR, "Failed to run the initializer: genauthz_state_init_bots()\n");
        return 1;
    }
    if (genauthz_state_init_work(jobdir) != 0) {
        syslog(LOG_ERR, "Failed to run the initializer: genauthz_state_init_jobs()\n");
        return 1;
    }

    return 0;
}
#endif

