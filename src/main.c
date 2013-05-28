
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>

#include <evhtp.h>
#include <libxml/parser.h>

#include "genauthz_main.h"
#include "genauthz_common.h"

#include "generalauthorization.h"
#include "genauthz_httprest.h"
#include "genauthz_conf.h"
#include "genauthz_callout_helper.h"
#include "genauthz_xacml_rule_parser.h"


#define CNC_CERT_FILE "/etc/generalauthorization/cert.pem"
#define CNC_PRIV_FILE "/etc/generalauthorization/cert.key"


/* The app_parent is apparent */
static struct app_parent *global_app_p;


static void
genauthz_sigterm(int this_signal) {
    fprintf(stderr, "Caught SIGTERM(%d) - stopping eventloop\n", this_signal);
    event_base_loopexit(global_app_p->evbase, NULL);
}

static void
genauthz_usage(void) {
    printf("%s\n", PACKAGE_STRING);
    printf("generalauthorizationd\n");
    printf("    --conf <path/to/configuration file>\n");
    printf("\n");
    exit(1);
}


int
main(int argc, char ** argv) {
    int i = 1;
    short got_conf = 0;
    char *syslog_ident = NULL;
    int syslog_flags = 0, syslog_facility = 0;
    char *policy_file = NULL;

    /* App initializers */
    global_app_p = calloc(sizeof(struct app_parent), 1);
    if (global_app_p == NULL) {
        fprintf(stderr, "Error: unable to allocate a few bytes...\n");
        return 1;
    }
    global_app_p->evbase = event_base_new();
    if (global_app_p->evbase == NULL) {
        fprintf(stderr, "Error: unable to allocate a few bytes for a base...\n");
        return 1;
    }
    global_app_p->evhtp = evhtp_new(global_app_p->evbase, NULL);
    if (global_app_p->evhtp == NULL) {
        fprintf(stderr, "Error: unable to allocate a few bytes for an evhtp base...\n");
        return 1;
    }
    TAILQ_INIT(&(global_app_p->listener_head));

    /* Commandline arguments & config parsing */
    for (i = 1; i < argc; i++) {
        if ((strcasecmp("--conf", argv[i]) == 0)  && (i < argc)) {
            if (configuration(global_app_p,
                              argv[i+1],
                              &policy_file,
                              &syslog_ident, &syslog_flags,
                              &syslog_facility) < 0) {
                return GA_BAD;
            }
            got_conf++;
            i++;
        } else {
            genauthz_usage();
        }
    }
    if (got_conf == 0) {
        fprintf(stderr, "Error: no configuration files found\n");
        goto cleanup;
    }

    /* Must have one listener */
    if (TAILQ_EMPTY(&(global_app_p->listener_head))) {
        fprintf(stderr, "Error: No listeners configured in the config file.\n");
    }

    /* Initializer */
    datatype_list_init();

    /* Policy rules */
    if (rule_parser(policy_file, &(global_app_p->xacml_policy)) == GA_GOOD) {
        printf("Policy Parsing success\n");
        print_loaded_policy(global_app_p->xacml_policy);
    } else {
        printf("Policy Parsing FAILED\n");
        goto cleanup;
    }

    /* Syslog init */
    openlog(syslog_ident, syslog_flags, syslog_facility);
    srand((unsigned)time(NULL));

    syslog(LOG_DEBUG, "Logging with SysLog ident: \"%s\"", syslog_ident);


    /* Init callbacks */
    if (genauthz_initialize_rule_callbacks(global_app_p->xacml_policy) == GA_GOOD) {
        printf("Callback initialization Success\n");
    } else {
        printf("Callback initialization FAILED\n");
        goto cleanup;
    }

    /* Initialize everything */
    evhtp_ssl_use_threads();

#if 0
    if (event_base_priority_init(get_event_base(), 3) < 0) {
        printf("Error: could not initialize the event_base with 2 priority levels\n");
        goto cleanup;
    }
#endif
    /* All the HTTP initialization */
    if (genauthz_httprest_init(global_app_p->evbase, global_app_p) != GA_GOOD) {
        syslog(LOG_ERR, "Error: could not register events and callbacks");
        goto cleanup;
    }

    /* Installing signal handlers */
    if (signal(SIGTERM, genauthz_sigterm) == SIG_ERR) {
        fprintf(stderr, "An error occurred while setting a signal handler.\n");
        return GA_BAD;;
    }

    /* Start working the service */
    event_base_loop(global_app_p->evbase, 0);
cleanup:
    xmlCleanupParser();

    free(policy_file);
    closelog();

    return GA_GOOD;
}

