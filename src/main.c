#include <syslog.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <evhtp.h>

#define _GNU_SOURCE
#include "confuse.h"

#include "genauthz_main.h"

#include "generalauthorization.h"
#include "genauthz_common.h"
#include "genauthz_httprest.h"



#define CNC_CERT_FILE "/etc/generalauthorization/cert.pem"
#define CNC_PRIV_FILE "/etc/generalauthorization/cert.key"


/* Global Variables */
struct event_base *main_base = NULL;
tq_listener_list_t listener_head;

/* Prototypes */
static void genauthz_usage(void);


/* functions */
struct event_base *
get_event_base(void) {
    return main_base;
}
void
set_event_base(struct event_base *base) {
    main_base = base;
}


static int
register_events_and_callbacks(evbase_t *evbase,
                              tq_listener_list_t listener_list) {
    /* All the HTTP initialization */
    if (genauthz_httprest_init(evbase, listener_list)) {
        goto cleanup;
    }

    return 0;
cleanup:
    return 1;
}

static void
genauthz_usage(void) {
    printf("%s\n", PACKAGE_STRING);
    printf("generalauthorizationd\n");
    printf("    --conf <path/to/configuration file>\n");
    printf("\n");
    exit(1);
}

/******************************/
static void print_func(cfg_opt_t *opt, unsigned int idx, FILE *fp)
{
    fprintf(fp, "%s(foo)", opt->name);
}

static void print_ask(cfg_opt_t *opt, unsigned int idx, FILE *fp)
{
    int value = cfg_opt_getnint(opt, idx);
    switch(value) {
        case 1:
            fprintf(fp, "yes");
            break;
        case 2:
            fprintf(fp, "no");
            break;
        case 3:
        default:
            fprintf(fp, "maybe");
            break;
    }
}

static int
cb_service_type(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result)
{
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
        return -1;
    }
    return 0;
}

static int
cb_answer(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result)
{
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
        return -1;
    }
    return 0;
}

static int
configuration(const char *configfile) {
    unsigned int i, j;
    struct tq_listener_s *p_listener = NULL;
    struct tq_service_s *p_service = NULL;
    cfg_t *cfg;
    unsigned n_listener, n_services;
    int ret;
    static cfg_opt_t service_opts[] = {
        CFG_INT_CB("type", NONE, CFGF_NONE, &cb_service_type),
        CFG_STR("uri", 0, CFGF_NONE),
        CFG_END()
    };
    static cfg_opt_t listener_opts[] = {
        CFG_STR("bindaddress", 0, CFGF_NONE),
        CFG_INT("port", 9001, CFGF_NONE),
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
        CFG_SEC("listener", listener_opts, CFGF_MULTI),
        /* CFG_FUNC("include", &cfg_include), */
        CFG_END()
    };

    cfg = cfg_init(opts, CFGF_NOCASE);

    /* set a validating callback function for bookmark sections */
    /* cfg_set_validate_func(cfg, "bookmark", &cb_validate_bookmark); */

    ret = cfg_parse(cfg, configfile);
    printf("ret == %d\n", ret);
    if (ret == CFG_FILE_ERROR) {
        perror("test.conf");
        return 1;
    } else if (ret == CFG_PARSE_ERROR) {
        fprintf(stderr, "parse error\n");
        return 2;
    }

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
        TAILQ_INIT(&(p_listener->services_head));


        printf("    bindaddress = %s\n", cfg_getstr(ls, "bindaddress"));
        printf("    port = %d\n", (int)cfg_getint(ls, "port"));
        /* printf("    password = %s\n", cfg_getstr(ls, "password")); */

        p_listener->bindip = cfg_getstr(ls, "bindaddress");
        p_listener->port   = (short)cfg_getint(ls, "port");

        n_services = cfg_size(ls, "service");
        printf("      %d\n", n_services);
        for (j = 0; j < n_services; j++) {
            cfg_t *serv = cfg_getnsec(ls, "service", i);
            if (serv == NULL) {
                goto cleanup;
            }

            p_service = malloc(sizeof(struct tq_service_s));
            if (p_service == NULL) {
                printf("Error: memory allocation problem, couldn't allocate %lu bytes\n",
                        sizeof(struct tq_service_s));
                goto cleanup;
            }

            printf("       uri = %s\n", cfg_getstr(serv, "uri"));
            service_type_t ltype = cfg_getint(serv, "type");
            printf("       type = %s\n", ltype == PDP ? "PDP" : ltype == PAP ? "PAP" : ltype == PEP ? "PEP" : "unknown");
            p_service->ltype = cfg_getint(serv, "type");
            p_service->uri   = cfg_getstr(serv, "uri");

            TAILQ_INSERT_TAIL(&(p_listener->services_head), p_service, entries);
        }

        TAILQ_INSERT_TAIL(&listener_head, p_listener, entries);
    }

    /* Using cfg_setint(), the integer value for the option ask-quit
     * is not verified by the value parsing callback.
     *
     *
     cfg_setint(cfg, "ask-quit", 4);
     printf("ask-quit == %ld\n", cfg_getint(cfg, "ask-quit"));
    */

    cfg_free(cfg);
    return 0;
cleanup:
    cfg_free(cfg);
    return -1;

}
/******************************/



int
main(int argc, char ** argv) {
    int i = 1;
    char *ident = "generalauthorization";

    /* Construct and register an event base */
    set_event_base(event_base_new());

    /* Initialize the listeners list */
    TAILQ_INIT(&listener_head);

    for (i = 1; i < argc; i++) {
        if ((strcasecmp("--conf", argv[i]) == 0)  && (i < argc)) {
            if (configuration(argv[i+1]) < 0) {
                return 1;
            }
            i++;
        } else {
            genauthz_usage();
        }
    }

    /* Must have a listener */
    if (TAILQ_EMPTY(&listener_head)) {
        printf("Error: No --listener options set.\n\n");
        genauthz_usage();
    }

    /* Syslog init */
    openlog(ident, LOG_NDELAY|LOG_PID, LOG_LOCAL3);
    srand((unsigned)time(NULL));

    printf("Logging with SysLog ident: \"%s\" on LOCAL3\n", ident);

    /* Initialize everything */
    evhtp_ssl_use_threads();
#if 1
    if (event_base_priority_init(get_event_base(), 3) < 0) {
        printf("Error: could not initialize the event_base with 2 priority levels\n");
        goto cleanup;
    }
#endif
    if (register_events_and_callbacks(get_event_base(),
                                      listener_head)) {
        printf("Error: could not register events and callbacks\n");
        goto cleanup;
    }

    printf("---\n");

    /* Start working the service */
    event_base_loop(get_event_base(), 0);

cleanup:
    closelog();

    return 0;
}

