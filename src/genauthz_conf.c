#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>

#define _GNU_SOURCE
#include "confuse.h"

#include "genauthz_main.h"
#include "genauthz_common.h"

#include "generalauthorization.h"
#include "genauthz_httprest.h"
#include "genauthz_conf.h"


static int
cb_syslog_options(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) {
    if(strcasecmp(value, "PID") == 0)
        *(service_type_t *)result = LOG_PID;
    else if(strcasecmp(value, "CONS") == 0)
        *(service_type_t *)result = LOG_CONS;
    else if(strcasecmp(value, "ODELAY") == 0)
        *(service_type_t *)result = LOG_ODELAY;
    else if(strcasecmp(value, "NDELAY") == 0)
        *(service_type_t *)result = LOG_NDELAY;
    else if(strcasecmp(value, "NOWAIT") == 0)
        *(service_type_t *)result = LOG_NOWAIT;
    else if(strcasecmp(value, "PERROR") == 0)
        *(service_type_t *)result = LOG_PERROR;
    else {
        cfg_error(cfg, "Invalid value for option %s: %s", opt->name, value);
        return GA_BAD;
    }
    return GA_GOOD;
}

static int
cb_syslog_facility(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) {
    if(strcasecmp(value, "auth") == 0)
        *(service_type_t *)result = LOG_AUTH;
    else if(strcasecmp(value, "authpriv") == 0)
        *(service_type_t *)result = LOG_AUTHPRIV;
    else if(strcasecmp(value, "cron") == 0)
        *(service_type_t *)result = LOG_CRON;
    else if(strcasecmp(value, "daemon") == 0)
        *(service_type_t *)result = LOG_DAEMON;
    else if(strcasecmp(value, "ftp") == 0)
        *(service_type_t *)result = LOG_FTP;
    else if(strcasecmp(value, "kern") == 0)
        *(service_type_t *)result = LOG_KERN;
    else if(strcasecmp(value, "local0") == 0)
        *(service_type_t *)result = LOG_LOCAL0;
    else if(strcasecmp(value, "local1") == 0)
        *(service_type_t *)result = LOG_LOCAL1;
    else if(strcasecmp(value, "local2") == 0)
        *(service_type_t *)result = LOG_LOCAL2;
    else if(strcasecmp(value, "local3") == 0)
        *(service_type_t *)result = LOG_LOCAL3;
    else if(strcasecmp(value, "local4") == 0)
        *(service_type_t *)result = LOG_LOCAL4;
    else if(strcasecmp(value, "local5") == 0)
        *(service_type_t *)result = LOG_LOCAL5;
    else if(strcasecmp(value, "local6") == 0)
        *(service_type_t *)result = LOG_LOCAL6;
    else if(strcasecmp(value, "local7") == 0)
        *(service_type_t *)result = LOG_LOCAL7;
    else if(strcasecmp(value, "lpr") == 0)
        *(service_type_t *)result = LOG_LPR;
    else if(strcasecmp(value, "mail") == 0)
        *(service_type_t *)result = LOG_MAIL;
    else if(strcasecmp(value, "news") == 0)
        *(service_type_t *)result = LOG_NEWS;
    else if(strcasecmp(value, "syslog") == 0)
        *(service_type_t *)result = LOG_SYSLOG;
    else if(strcasecmp(value, "user") == 0)
        *(service_type_t *)result = LOG_USER;
    else if(strcasecmp(value, "uucp") == 0)
        *(service_type_t *)result = LOG_UUCP;
    else {
        cfg_error(cfg, "Invalid value for option %s: %s", opt->name, value);
        return -1;
    }
    return 0;
}
static int
cb_service_type(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) {
    if(strcasecmp(value, "control") == 0)
        *(service_type_t *)result = CONTROL;
    else if(strcasecmp(value, "pap") == 0)
        *(service_type_t *)result = PAP;
    else if(strcasecmp(value, "pdp") == 0)
        *(service_type_t *)result = PDP;
    else if(strcasecmp(value, "pep") == 0)
        *(service_type_t *)result = PEP;
    else {
        cfg_error(cfg, "Invalid value for option %s: %s", opt->name, value);
        return GA_BAD;
    }
    return GA_GOOD;
}

static int
cb_answer(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) {
    if(strcasecmp(value, "no") == 0)
        *(answer_t *)result = NO;
    else if(strcasecmp(value, "yes") == 0)
        *(answer_t *)result = YES;
    else if(strcasecmp(value, "optional") == 0)
        *(answer_t *)result = OPTIONAL;
    else if(strcasecmp(value, "maybe") == 0)
        *(answer_t *)result = MAYBE;
    else {
        cfg_error(cfg, "Invalid value for option %s: %s", opt->name, value);
        return GA_BAD;
    }
    return GA_GOOD;
}

int
configuration(struct app_parent *app_p,
              const char *configfile,
              char **syslog_ident,
              int *syslog_flags,
              int *syslog_facility) {
    unsigned int i, j;
    struct tq_listener_s *p_listener = NULL;
    struct tq_service_s *p_service = NULL;
    char *buf = NULL;
    cfg_t *cfg;
    unsigned n_listener, n_services;
    int ret;
    static cfg_opt_t syslog_opts[] = {
        CFG_STR("ident", 0, CFGF_NONE),
        CFG_INT_CB("facility", NONE, CFGF_NONE, &cb_syslog_facility),
        CFG_INT_LIST_CB("options", 0, CFGF_NONE, &cb_syslog_options),
        CFG_END()
    };
    static cfg_opt_t service_opts[] = {
        CFG_INT_CB("type", NONE, CFGF_NONE, &cb_service_type),
        CFG_STR("uri", 0, CFGF_NONE),
        CFG_END()
    };
    static cfg_opt_t listener_opts[] = {
        CFG_STR("bindaddress", 0, CFGF_NONE),
        CFG_INT("port", 9001, CFGF_NONE),
        CFG_INT("backlog", 1024, CFGF_NONE),
        CFG_STR("cert", 0, CFGF_NONE),
        CFG_STR("key", 0, CFGF_NONE),
        CFG_STR("cafile", 0, CFGF_NONE),
        CFG_STR("capath", 0, CFGF_NONE),
        CFG_STR("password", 0, CFGF_NONE),
        CFG_INT_CB("clientauth", NONE, CFGF_NONE, &cb_answer),
        CFG_INT_CB("rfc3820", NONE, CFGF_NONE, &cb_answer),
        CFG_SEC("service", service_opts, CFGF_MULTI),
        CFG_END()
    };
    cfg_opt_t opts[] = {
        CFG_INT("threads", 8, CFGF_NONE),
        CFG_SEC("syslog", syslog_opts, CFGF_NONE),
        CFG_SEC("listener", listener_opts, CFGF_MULTI),
        CFG_END()
    };

    cfg = cfg_init(opts, CFGF_NOCASE);

    /* set a validating callback function for bookmark sections */
    /* cfg_set_validate_func(cfg, "bookmark", &cb_validate_bookmark); */

    ret = cfg_parse(cfg, configfile);
    if (ret == CFG_FILE_ERROR) {
        fprintf(stderr, "Error: could not open or read the configuration file "
               "\"%s\".\n", configfile);
        return GA_BAD;
    } else if (ret == CFG_PARSE_ERROR) {
        fprintf(stderr, "Error: parse error in the configuration file "
               "\"%s\".\n", configfile);
        return GA_BAD;
    }

    /* Syslog */
    cfg_t *syslog_sec = cfg_getsec(cfg, "syslog");
    if (syslog_sec == NULL) {
        fprintf(stderr, "Error: no \"syslog\" section found in the "
                        "configuration file \"%s\"\n", configfile);
    } else {
        printf("found syslog\n");
        printf("    ident = %s\n", cfg_getstr(syslog_sec, "ident"));
        *syslog_ident = strdup(cfg_getstr(syslog_sec, "ident"));
        printf("    facility = %ld\n", cfg_getint(syslog_sec, "facility"));
        *syslog_facility = cfg_getint(syslog_sec, "facility");

        printf("BUG\n");
        for (i = 0; i < cfg_size(syslog_sec, "options"); i++)
                printf("options[%d] == %ld\n",
                       i, cfg_getnint(syslog_sec, "options", i));

        *syslog_flags = LOG_PID|LOG_NDELAY|LOG_PERROR;
        printf("BUG\n");
    }

    /* Listeners */
    n_listener = cfg_size(cfg, "listener");
    printf("%d configured listeners:\n", n_listener);
    for (i = 0; i < n_listener; i++) {
        cfg_t *ls = cfg_getnsec(cfg, "listener", i);
        if (ls == NULL) {
            goto cleanup;
        }

        p_listener = malloc(sizeof(struct tq_listener_s));
        if (p_listener == NULL) {
            printf("Error: memory allocation problem, couldn't allocate %lu bytes\n",
                    sizeof(struct tq_listener_s));
            goto cleanup;
        }
        memset(p_listener, 0, sizeof(struct tq_listener_s));
        TAILQ_INIT(&(p_listener->services_head));

        /* Settings */
        p_listener->bindip  = strdup(cfg_getstr(ls, "bindaddress"));
        p_listener->port    = (short)cfg_getint(ls, "port");
        p_listener->backlog = (short)cfg_getint(ls, "backlog");

        n_services = cfg_size(ls, "service");
        printf("      %d\n", n_services);
        for (j = 0; j < n_services; j++) {
            cfg_t *serv = cfg_getnsec(ls, "service", j);
            if (serv == NULL) {
                goto cleanup;
            }

            p_service = malloc(sizeof(struct tq_service_s));
            if (p_service == NULL) {
                printf("Error: memory allocation problem, couldn't allocate %lu bytes\n",
                        sizeof(struct tq_service_s));
                goto cleanup;
            }
            memset(p_service, 0, sizeof(struct tq_service_s));

            p_service->ltype = cfg_getint(serv, "type");
            p_service->uri = cfg_getstr(serv, "uri");
            if (p_service->uri && p_service->uri[0] == '/') {
                p_service->uri = strdup(p_service->uri);
            } else {
                buf = malloc(strlen(p_service->uri) + 2);
                if (buf == NULL) {
                    goto cleanup;
                }
                snprintf(buf, strlen(p_service->uri) + 2, "/%s", p_service->uri);
                p_service->uri = buf;
            }
            printf("       uri = %s\n", p_service->uri);
            printf("       type = %s\n", p_service->ltype == PDP ? "PDP" : p_service->ltype == PAP ? "PAP" : p_service->ltype == PEP ? "PEP" : "unknown");

            TAILQ_INSERT_TAIL(&(p_listener->services_head), p_service, next);
        }

        TAILQ_INSERT_TAIL(&(app_p->listener_head), p_listener, next);
    }
    app_p->thread_cnt = (short)cfg_getint(cfg, "threads");

    cfg_free(cfg);
    return GA_GOOD;
cleanup:
    cfg_free(cfg);
    return GA_BAD;

}
