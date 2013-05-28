#include "genauthz_callout_helper.h"


int
genauthz_initialize_rule_callbacks(struct xacml_policy_s *xacml_policy) {
    void *ph;
    struct tq_xacml_rule_s *rule;
    struct tq_xacml_callout_s *callout;

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
        }
    }

    return GA_GOOD;
}


