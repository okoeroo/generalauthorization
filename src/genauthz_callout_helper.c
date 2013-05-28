#include "genauthz_callout_helper.h"


int
genauthz_initialize_rule_callbacks(struct xacml_policy_s *xacml_policy) {
    struct tq_xacml_rule_s *rule;
    struct tq_xacml_callout_s *callout;
    void *ph;
    void (*genauthz_rule_hit_fp)(request_mngr_t *request_mngr, tq_xacml_rule_t *trigger_by_rule) = NULL;

    if (!xacml_policy)
        return GA_BAD;

    TAILQ_FOREACH(rule, &(xacml_policy->xacml_rule_list), next) {
        TAILQ_FOREACH(callout, &(rule->callouts), next) {
            ph = dlopen(callout->plugin_path, RTLD_LOCAL|RTLD_NOW);
            if (!ph) {
                syslog(LOG_ERR, "Error: could not use/load the plugin from \"%s\".",
                                callout->plugin_path);
                fprintf(stderr, "Error: could not use/load the plugin from \"%s\".\n",
                                callout->plugin_path);
                return GA_BAD;
            }
            /* Record the plugin handle */
            callout->handle = ph;

            *(void **)(&genauthz_rule_hit_fp) = dlsym(callout->handle, callout->function_name);
            if (!genauthz_rule_hit_fp) {
                syslog(LOG_ERR, "Error: could not find the function \"%s\" in \"%s\".",
                                callout->function_name, callout->plugin_path);
                fprintf(stderr, "Error: could not find the function \"%s\" in \"%s\".\n",
                                callout->function_name, callout->plugin_path);
                return GA_BAD;
            }
            /* Record the function pointer */
            callout->rule_hit_cb = genauthz_rule_hit_fp;
        }
    }

    return GA_GOOD;
}


