
#include "genauthz_normalized_xacml.h"
#include "genauthz_xacml_rule_parser.h"


static int
cb_rule_result_decision(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) {
    if(strcasecmp(value, "permit") == 0)
        *(enum ga_xacml_decision_e *)result = GA_XACML_DECISION_PERMIT;
    else if(strcasecmp(value, "deny") == 0)
        *(enum ga_xacml_decision_e *)result = GA_XACML_DECISION_DENY;
    else if(strcasecmp(value, "indeterminate") == 0)
        *(enum ga_xacml_decision_e *)result = GA_XACML_DECISION_INDETERMINATE;
    else if(strcasecmp(value, "notapplicable") == 0)
        *(enum ga_xacml_decision_e *)result = GA_XACML_DECISION_NOTAPPLICABLE;
    else {
        cfg_error(cfg, "Invalid value for option %s: %s", opt->name, value);
        return GA_BAD;
    }
    return GA_GOOD;
}

static int
cb_rule_composition(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) {
    if(strcasecmp(value, "anyof") == 0)
        *(enum ga_rule_composition_e *)result = GA_RULE_COMPOSITION_ANYOF;
    else if(strcasecmp(value, "all") == 0)
        *(enum ga_rule_composition_e *)result = GA_RULE_COMPOSITION_ALL;
    else if(strcasecmp(value, "one") == 0)
        *(enum ga_rule_composition_e *)result = GA_RULE_COMPOSITION_ONE;
    else {
        cfg_error(cfg, "Invalid value for option %s: %s", opt->name, value);
        return GA_BAD;
    }
    return GA_GOOD;
}

int
rule_parser(char *policy_file,
            tq_xacml_rule_list_t xacml_policy_rule_list) {
    int ret, i, n_rules, n_rule;
    cfg_t *cfg;
    struct tq_xacml_rule_s *xacml_policy_rule;

    static cfg_opt_t result_opts[] = {
        CFG_INT_CB("decision", NONE, CFGF_NONE, &cb_rule_result_decision),
        CFG_END()
    };
    static cfg_opt_t category_opts[] = {
        CFG_STR("attributeid", 0, CFGF_NONE),
        CFG_STR("function", 0, CFGF_NONE),
        CFG_STR("value", 0, CFGF_NONE),
        CFG_END()
    };
    static cfg_opt_t rule_opts[] = {
        CFG_INT_CB("composition", NONE, CFGF_NONE, &cb_rule_composition),
        CFG_SEC("subject", category_opts, CFGF_MULTI),
        CFG_SEC("action", category_opts, CFGF_MULTI),
        CFG_SEC("resource", category_opts, CFGF_MULTI),
        CFG_SEC("environment", category_opts, CFGF_MULTI),
        CFG_SEC("result", result_opts, CFGF_MULTI),
        CFG_END()
    };
    cfg_opt_t opts[] = {
        CFG_STR_LIST("rules", 0, CFGF_NONE),
        CFG_SEC("rule", rule_opts, CFGF_MULTI | CFGF_TITLE),
        CFG_END()
    };

    cfg = cfg_init(opts, CFGF_NOCASE);

    ret = cfg_parse(cfg, policy_file);
    if (ret == CFG_FILE_ERROR) {
        fprintf(stderr, "Error: could not open or read the configuration file "
               "\"%s\".\n", policy_file);
        goto cleanup;
    } else if (ret == CFG_PARSE_ERROR) {
        fprintf(stderr, "Error: parse error in the configuration file "
               "\"%s\".\n", policy_file);
        goto cleanup;
    }

    /* Work the config */
    n_rules = cfg_size(cfg, "rules");
    for (i = 0; i < n_rules; i++) {
        printf("Configured rule: %s\n", cfg_getnstr(cfg, "rules", i));
    }

    n_rule = cfg_size(cfg, "rule");
    for (i = 0; i < n_rule; i++) {
        cfg_t *rl = cfg_getnsec(cfg, "rule", i);
        int use_it = 0;

        n_rules = cfg_size(cfg, "rules");
        for (i = 0; i < n_rules; i++) {
            if (cfg_title(rl) &&
                strcasecmp(cfg_title(rl), cfg_getnstr(cfg, "rules", i)) == 0) {
                use_it = 1;
                break;
            }
        }
        if (!use_it) {
            break;
        }

        xacml_policy_rule = malloc(sizeof(struct tq_xacml_rule_s));
        if (xacml_policy_rule == NULL) {
            goto cleanup;
        }

        xacml_policy_rule->name = strdup(cfg_title(rl));
        xacml_policy_rule->composition = (enum ga_rule_composition_e)cfg_getint(rl, "composition");
        TAILQ_INIT(&(xacml_policy_rule->match_values_list));
        TAILQ_INIT(&(xacml_policy_rule->inherited_rules));

        /* categories */
        cat = cfg_getsec(rl, "subject");
        if (cat) {
        }
        cat = cfg_getsec(rl, "action");
        if (cat) {
        }
        cat = cfg_getsec(rl, "resource");
        if (cat) {
        }
        cat = cfg_getsec(rl, "environment");
        if (cat) {
        }

        /* result */
        cat = cfg_getsec(rl, "result");
        if (cat) {
        }

        TAILQ_INSERT_TAIL(&xacml_policy_rule_list, xacml_policy_rule, next);
    }


    cfg_free(cfg);
    return GA_GOOD;
cleanup:
    cfg_free(cfg);
    return GA_BAD;

}
