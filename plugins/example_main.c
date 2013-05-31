#include "example_main.h"


int
example_plugin_init(tq_xacml_callout_t *callout) {
    int i;
    int argc;
    char **argv;
    char *test;

    argc = genauthz_callout_get_argc(callout);
    argv = genauthz_callout_get_argv(callout);

    for (i = 0; i < argc; i++) {
        printf("Argv[%d]: %s\n", i, argv[i]);
    }

    test = strdup("w00t w00t");
    genauthz_callout_set_aux(callout, test);
    return 0;
}

void
example_plugin_uninit(tq_xacml_callout_t *callout) {
    printf("%s\n", (char *)genauthz_callout_get_aux(callout));
    return;
}

void
example_plugin_rule_hit(request_mngr_t *request_mngr,
                        tq_xacml_rule_t *rule,
                        tq_xacml_callout_t *callout) {
    printf("Rule \"%s\" hit! -- %s\n", rule->name, __func__);

    print_normalized_xacml_request(request_mngr->xacml_req);
    print_normalized_xacml_response(request_mngr->xacml_res);
    print_loaded_policy(request_mngr->app->parent->xacml_policy);

    printf("%s\n", (char *)genauthz_callout_get_aux(callout));

    return;
}


