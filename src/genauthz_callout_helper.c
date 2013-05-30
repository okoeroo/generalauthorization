#include "genauthz_callout_helper.h"


int
genauthz_initialize_rule_callbacks(struct xacml_policy_s *xacml_policy) {
    struct tq_xacml_rule_s *rule;
    struct tq_xacml_callout_s *callout;

    if (!xacml_policy)
        return GA_BAD;

    TAILQ_FOREACH(rule, &(xacml_policy->xacml_rule_list), next) {
        TAILQ_FOREACH(callout, &(rule->callouts), next) {
            /* Record the plugin handle */
            callout->handle = dlopen(callout->plugin_path, RTLD_LOCAL|RTLD_NOW);
            if (!callout->handle) {
                syslog(LOG_ERR, "Error: could not use/load the plugin from \"%s\".",
                                callout->plugin_path);
                fprintf(stderr, "Error: could not use/load the plugin from \"%s\".\n",
                                callout->plugin_path);
                return GA_BAD;
            }

            /* Record the function pointer */
            callout->rule_hit_cb = (genauthz_rule_hit_cb)dlsym(callout->handle,
                                                               callout->function_name);
            if (!callout->rule_hit_cb) {
                syslog(LOG_ERR, "Error: could not find the function \"%s\" in \"%s\".",
                                callout->function_name, callout->plugin_path);
                fprintf(stderr, "Error: could not find the function \"%s\" in \"%s\".\n",
                                callout->function_name, callout->plugin_path);
                return GA_BAD;
            }

            /* Add a argc, argv like interface */
        }
    }

    return GA_GOOD;
}


