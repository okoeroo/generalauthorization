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


evthr_t *
get_request_thr(evhtp_request_t * request) {
    evhtp_connection_t * htpconn;
    evthr_t            * thread;

    htpconn = evhtp_request_get_connection(request);
    thread  = htpconn->thread;

    return thread;
}

int
accept_format(evhtp_request_t *req) {
    const char * accept_h = NULL;

    /* Search the HTTP headers for the 'accept:' tag */
    if ((accept_h = evhtp_header_find(req->headers_in, "accept"))) {
        if (strcmp("application/json", accept_h) == 0) {
            return TYPE_APP_JSON;
        } else if (strcmp("application/xml", accept_h) == 0) {
            return TYPE_APP_XML;
        } else if (strcmp("application/xacml+xml", accept_h) == 0) {
            return TYPE_APP_XACML_XML;
        } else if (strcmp("application/xacml+json", accept_h) == 0) {
            return TYPE_APP_XACML_JSON;
        } else if (strcmp("*/*", accept_h) == 0) {
            return TYPE_APP_ALL;
        } else {
            return TYPE_APP_UNKNOWN;
        }
    }
    /* The default answer is *//* */
    return TYPE_APP_ALL;
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
    syslog(LOG_DEBUG, "%s", __func__);

    /* All ok */
    http_res = EVHTP_RES_OK;
    evhtp_send_reply(req, http_res);
    return;
}


/* Functions */
int
genauthz_httprest_init(evbase_t * evbase,
                       tq_listener_list_t listener_list
                      ) {
    struct passwd *pwd = NULL;
    struct tq_listener_s *p_listener, *tmp_p_listener;
    struct tq_service_s *p_service, *tmp_p_service;

    for (p_listener = TAILQ_FIRST(&listener_list);
         p_listener != NULL;
         tmp_p_listener = TAILQ_NEXT(p_listener, entries),
                p_listener = tmp_p_listener) {

        p_listener->evhtp = evhtp_new(evbase, NULL);
        if (p_listener->evhtp == NULL) {
            syslog(LOG_ERR, "Failed on evhtp_new()");
            goto cleanup;
        }
        syslog(LOG_DEBUG, "Created evhtp base");

        /* Setup security context */
        if (p_listener->scfg) {
            evhtp_ssl_init(p_listener->evhtp, p_listener->scfg);
        }

        /* Bind */
        if (evhtp_bind_socket(p_listener->evhtp, p_listener->bindip,
                              p_listener->port, 1024) != 0) {
            syslog(LOG_ERR, "Failed to bind a listener to \"%s\" on port \'%d\'",
                            p_listener->bindip, p_listener->port);
            goto cleanup;
        } else {
            syslog(LOG_INFO, "Listening on \"%s\" on port \'%d\'",
                            p_listener->bindip, p_listener->port);
        }

        for (p_service = TAILQ_FIRST(&(p_listener->services_head));
             p_service != NULL;
             tmp_p_service = TAILQ_NEXT(p_service, entries),
                    p_service = tmp_p_service) {
            syslog(LOG_ERR, "URI: \"%s\"", p_service->uri);

            /* Service type switcher */
            switch(p_service->ltype) {
                case PDP:
                    if (evhtp_set_cb(p_listener->evhtp,
                                     p_service->uri,
                                     pdp_cb,
                                     p_listener) == NULL) {
                        syslog(LOG_ERR, "Failed to set the PDP callback for the URI \"%s\"", p_service->uri);
                        goto cleanup;
                    } else {
                        syslog(LOG_INFO, "Set the callback \"generic_http_cb()\" for the URI \"%s\"", p_service->uri);
                    }
                    break;
                default:
                    if (evhtp_set_cb(p_listener->evhtp,
                                     p_service->uri,
                                     generic_http_cb,
                                     p_listener) == NULL) {
                        syslog(LOG_ERR, "Failed to set the generic callback for the URI \"%s\"", p_service->uri);
                        goto cleanup;
                    } else {
                        syslog(LOG_INFO, "Set the callback \"generic_http_cb()\" for the URI \"%s\"", p_service->uri);
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
                setegid(getgid());
            }
            seteuid(getuid());
        } else {
            /* Lower privs after bind to 'okoeroo' or 'nobody' */
            pwd = getpwnam("nobody");
            if (pwd == NULL) {
                return 1;
            }
            if (getegid() == 0) {
                setegid(pwd->pw_gid);
                setgid(pwd->pw_gid);
            }
            setuid(pwd->pw_uid);
            seteuid(pwd->pw_uid);
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

