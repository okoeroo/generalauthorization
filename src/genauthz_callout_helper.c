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

            /* Record the genauthz_plugin_init_cb pointer */
            callout->plugin_init_cb = (genauthz_plugin_init_cb)dlsym(callout->handle,
                                                                     callout->func_name_init);
            if (!callout->plugin_init_cb) {
                syslog(LOG_WARNING, "Warning: could not find the function \"%s\" in \"%s\".",
                                    callout->func_name_init, callout->plugin_path);
                fprintf(stderr, "Warning: could not find the function \"%s\" in \"%s\".\n",
                                callout->func_name_init, callout->plugin_path);
            }

            /* Record the genauthz_plugin_uninit_cb pointer */
            callout->plugin_uninit_cb = (genauthz_plugin_uninit_cb)dlsym(callout->handle,
                                                                         callout->func_name_uninit);
            if (!callout->plugin_uninit_cb) {
                syslog(LOG_WARNING, "Warning: could not find the function \"%s\" in \"%s\".",
                                    callout->func_name_uninit, callout->plugin_path);
                fprintf(stderr, "Warning: could not find the function \"%s\" in \"%s\".\n",
                                callout->func_name_uninit, callout->plugin_path);
            }

            /* Record the rule_hit_cb pointer */
            callout->rule_hit_cb = (genauthz_rule_hit_cb)dlsym(callout->handle,
                                                               callout->func_name_rule_hit);
            if (!callout->rule_hit_cb) {
                syslog(LOG_ERR, "Error: could not find the function \"%s\" in \"%s\".",
                                callout->func_name_rule_hit, callout->plugin_path);
                fprintf(stderr, "Error: could not find the function \"%s\" in \"%s\".\n",
                                callout->func_name_rule_hit, callout->plugin_path);
                return GA_BAD;
            }

            /* initializer function calling... */
            if (callout->plugin_init_cb) {
                /* Execute the plugin's initialization function with argc and argv as input */
                if (callout->plugin_init_cb(callout) < 0) {
                    syslog(LOG_ERR, "Error: failure in initialization of plugin \"%s\" for rule \"%s\".",
                                    callout->plugin_path, rule->name);
                    callout->state = GA_XACML_CALLOUT_ERROR;
                    return GA_BAD;
                } else {
                    callout->state = GA_XACML_CALLOUT_INIT;
                }
            }
        }
    }

    return GA_GOOD;
}


/* Execute the callouts per hit rule */
int
genauthz_execute_rule_callouts(request_mngr_t *request_mngr,
                               struct tq_xacml_rule_s *rule) {
    struct tq_xacml_callout_s *callout;
    int rc;

    TAILQ_FOREACH(callout, &(rule->callouts), next) {
        /* Make it so! */
        rc = callout->rule_hit_cb(request_mngr, rule, callout);
        if (rc < 0)
            return GA_BAD; /* TODO error message */
    }
    return GA_GOOD;
}


/* Plug-in helper function */
int
genauthz_callout_get_argc(struct tq_xacml_callout_s *callout) {
    if (!callout)
        return 0;
    return callout->argc;
}

char **
genauthz_callout_get_argv(struct tq_xacml_callout_s *callout) {
    if (!callout)
        return NULL;
    return callout->argv;
}
void *
genauthz_callout_get_aux(struct tq_xacml_callout_s *callout) {
    if (!callout)
        return NULL;
    return callout->rule_hit_arg;
}

void
genauthz_callout_set_aux(struct tq_xacml_callout_s *callout, void *aux) {
    if (!callout)
        return;

    callout->rule_hit_arg = aux;
    return;
}

