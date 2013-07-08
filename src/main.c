#include "ga_config.h"
#include "genauthz/genauthz_main.h"


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
    printf("    --help\n");
    printf("    -v | --verbose\n");
    printf("    --conf <path/to/configuration file>\n");
    printf("\n");
    exit(1);
}


static int
daemonize(void) {
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        return -1;
    } else if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        return -1;
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        /* Log the failure */
        return -1;
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return 0;
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
            if (got_conf) {
                fprintf(stderr, "Error: second \"--conf\" found in the commandline arguments.\n");
                return 1;
            }
            global_app_p->conf_file = argv[i+1];
            got_conf++;
            i++;
        } else if ((strcasecmp("--verbose", argv[i]) == 0) || (strcmp("-v", argv[i]) == 0)){
            global_app_p->verbose += 1;
        } else if ((strcasecmp("--foreground", argv[i]) == 0) || (strcmp("-f", argv[i]) == 0)){
            global_app_p->foreground = 1;
        } else {
            genauthz_usage();
        }
    }
    if (got_conf == 0) {
        fprintf(stderr, "Error: no configuration files found\n");
        goto cleanup;
    }

    if (configuration(global_app_p,
                      global_app_p->conf_file,
                      &policy_file,
                      &syslog_ident, &syslog_flags,
                      &syslog_facility) < 0) {
        return GA_BAD;
    }

    /* Must have one listener */
    if (TAILQ_EMPTY(&(global_app_p->listener_head))) {
        fprintf(stderr, "Error: No listeners configured in the config file.\n");
    }

    /* Initializer */
    datatype_list_init();

    /* Policy rules */
    if (rule_parser(policy_file, &(global_app_p->xacml_policy)) == GA_GOOD) {
        if (global_app_p->verbose) {
            printf("Policy Parsing success\n");
            print_loaded_policy(global_app_p->xacml_policy);
        }
    } else {
        fprintf(stderr, "Error: Policy Parsing FAILED\n");
        goto cleanup;
    }

    /* Syslog init */
    openlog(syslog_ident, syslog_flags, syslog_facility);
    srand((unsigned)time(NULL));

    if (global_app_p->verbose) {
        syslog(LOG_DEBUG, "Logging with SysLog ident: \"%s\"", syslog_ident);
    }

    /* Init callbacks */
    if (genauthz_initialize_rule_callbacks(global_app_p->xacml_policy) != GA_GOOD) {
        syslog(LOG_ERR, "Error: Callback initialization FAILED");
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
        syslog(LOG_ERR, "Error: An error occurred while setting a signal handler.");
        return GA_BAD;
    }

    if (!global_app_p->foreground) {
        /* Daemonize when all is done, and we're not requested to run in the
         * foreground */
        if (daemonize() < 0) {
            syslog(LOG_ERR, "Error: Failed to daemonize the service.");
        }
    }

    /* Start working the service */
    event_base_loop(global_app_p->evbase, 0);
cleanup:
    xmlCleanupParser();

    free(policy_file);
    closelog();

    return GA_GOOD;
}

