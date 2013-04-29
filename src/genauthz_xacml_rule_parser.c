
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
cb_rule_logical(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) {
    if(strcasecmp(value, "AND") == 0)
        *(enum ga_xacml_logical_e *)result = GA_XACML_LOGICAL_AND;
    else if(strcasecmp(value, "OR") == 0)
        *(enum ga_xacml_logical_e *)result = GA_XACML_LOGICAL_OR;
    else if(strcasecmp(value, "NOT") == 0)
        *(enum ga_xacml_logical_e *)result = GA_XACML_LOGICAL_NOT;
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
unsigned char *
u_strdup(unsigned char *src);

unsigned char *
u_strdup(unsigned char *src) {
    unsigned char *dst;
    size_t len;

    if (!src)
        return NULL;

    len = strlen((char *)src);
    dst = malloc(len + 1);
    if (dst == NULL)
        return NULL;
    else
        memcpy(dst, src, len + 1);

    return dst;
}

static int
rule_attribute_parser(tq_xacml_attribute_list_t attr_list,
                      cfg_t *attr) {
    struct tq_xacml_attribute_s *x_attribute = NULL;
    struct tq_xacml_attribute_value_s *x_attribute_value = NULL;

    if (!attr) {
        return GA_BAD;
    }

    if (cfg_getstr(attr, "attributeid") &&
        cfg_getstr(attr, "function")) {

        x_attribute = create_normalized_xacml_attribute();
        if (x_attribute == NULL) {
            goto fail;
        }

        x_attribute->id = u_strdup((unsigned char *)cfg_getstr(attr, "attributeid"));
        if (x_attribute->id == NULL) {
            delete_normalized_xacml_attribute(x_attribute);
            goto fail;
        }

        if (cfg_getstr(attr, "value")) {
            x_attribute_value = create_normalized_xacml_attribute_value();
            if (x_attribute_value == NULL) {
                goto fail;
            }
            x_attribute_value->datatype_id = NULL;
            x_attribute_value->datatype    = GA_XACML_DATATYPE_STRING;
            x_attribute_value->data        = u_strdup((unsigned char *)cfg_getstr(attr, "value"));

            TAILQ_INSERT_TAIL(&(x_attribute->values), x_attribute_value, next);
        }
        TAILQ_INSERT_TAIL(&(attr_list), x_attribute, next);
    }

    return GA_GOOD;
fail:
    delete_normalized_xacml_attribute(x_attribute);
    return GA_BAD;
}

static int
rule_category_parser(tq_xacml_rule_match_values_list_t rule_match_list_value_list,
                     cfg_t *cat,
                     enum ga_xacml_category_e cat_type) {
    struct tq_xacml_category_s *x_category = NULL;
    cfg_t *attr;
    int i, n_rule;

    if (!cat)
        return GA_BAD;

    /* Create category */
    x_category = create_normalized_xacml_category();
    if (x_category == NULL)
        return GA_BAD;
    x_category->type = cat_type;

    /* Walk explicit attributes */
    n_rule = cfg_size(cat, "attribute");
    for (i = 0; i < n_rule; i++) {
        attr = cfg_getnsec(cat, "attribute", i);
        rule_attribute_parser(x_category->attributes, attr);
    }

    /* Walk explicit attribute */
    if (cfg_getstr(cat, "attributeid") &&
        cfg_getstr(cat, "function") &&
        cfg_getstr(cat, "value")) {

        rule_attribute_parser(x_category->attributes, cat);
    }

    return GA_GOOD;
}


int
rule_parser(char *policy_file,
            struct xacml_policy_s **xacml_policy) {
    int ret, i, n_rules, n_rule;
    cfg_t *cfg, *cat;
    struct tq_xacml_rule_s *xacml_policy_rule;

    static cfg_opt_t result_opts[] = {
        CFG_INT_CB("decision", NONE, CFGF_NONE, &cb_rule_result_decision),
        CFG_END()
    };
    static cfg_opt_t attribute_opts[] = {
        CFG_STR("attributeid", 0, CFGF_NONE),
        CFG_STR("function", 0, CFGF_NONE),
        CFG_STR("value", 0, CFGF_NONE),
        CFG_END()
    };
    static cfg_opt_t category_opts[] = {
        CFG_SEC("attribute", attribute_opts, CFGF_MULTI),
        CFG_STR("attributeid", 0, CFGF_NONE),
        CFG_STR("function", 0, CFGF_NONE),
        CFG_STR("value", 0, CFGF_NONE),
        CFG_END()
    };
    static cfg_opt_t rule_opts[] = {
        CFG_INT_CB("logical", NONE, CFGF_NONE, &cb_rule_logical),
        CFG_SEC("subject", category_opts, CFGF_MULTI),
        CFG_SEC("action", category_opts, CFGF_MULTI),
        CFG_SEC("resource", category_opts, CFGF_MULTI),
        CFG_SEC("environment", category_opts, CFGF_MULTI),
        CFG_SEC("result", result_opts, CFGF_MULTI),
        CFG_END()
    };
    cfg_opt_t opts[] = {
        CFG_STR_LIST("rules", 0, CFGF_NONE),
        CFG_INT_CB("composition", NONE, CFGF_NONE, &cb_rule_composition),
        CFG_SEC("rule", rule_opts, CFGF_MULTI | CFGF_TITLE),
        CFG_END()
    };

    /* Main struct */
    *xacml_policy = malloc(sizeof(struct xacml_policy_s));
    if (*xacml_policy == NULL) {
        return GA_BAD;
    }
    (*xacml_policy)->composition = GA_RULE_COMPOSITION_ANYOF;
    TAILQ_INIT(&((*xacml_policy)->xacml_rule_list));

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

        /* xacml_policy_rule->composition = cfg_getint(rl, "composition"); */

    /* Work the config */
    n_rules = cfg_size(cfg, "rules");
    for (i = 0; i < n_rules; i++) {
        printf("Configured rule: %s\n", cfg_getnstr(cfg, "rules", i));
    }

    /* One rules */
    if (cfg_size(cfg, "rules") == 0) {
        fprintf(stderr, "Error: No \"rules\" configured. Please create a whitelist of rules.\n");
        goto cleanup;
    }

    /* Walk rules */
    n_rule = cfg_size(cfg, "rule");
    for (i = 0; i < n_rule; i++) {
        cfg_t *rl = cfg_getnsec(cfg, "rule", i);
        int use_it = 0;

        /* Check if rule is enabled */
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

        /* Check if Rule Name is unique */
        xacml_policy_rule->name = strdup(cfg_title(rl));
        xacml_policy_rule->logical = cfg_getint(rl, "logical");
        TAILQ_INIT(&(xacml_policy_rule->match_values_list));
        TAILQ_INIT(&(xacml_policy_rule->inherited_rules));

        /* categories */
        cat = cfg_getsec(rl, "subject");
        if (cat) {
            if (rule_category_parser(xacml_policy_rule->match_values_list,
                                     cat,
                                     GA_XACML_CATEGORY_SUBJECT) == GA_BAD) {
                goto cleanup;
            }
        }
        cat = cfg_getsec(rl, "action");
        if (cat) {
            if (rule_category_parser(xacml_policy_rule->match_values_list,
                                     cat,
                                     GA_XACML_CATEGORY_ACTION) == GA_BAD) {
                goto cleanup;
            }
        }
        cat = cfg_getsec(rl, "resource");
        if (cat) {
            if (rule_category_parser(xacml_policy_rule->match_values_list,
                                     cat,
                                     GA_XACML_CATEGORY_RESOURCE) == GA_BAD) {
                goto cleanup;
            }
        }
        cat = cfg_getsec(rl, "environment");
        if (cat) {
            if (rule_category_parser(xacml_policy_rule->match_values_list,
                                     cat,
                                     GA_XACML_CATEGORY_ENVIRONMENT) == GA_BAD) {
                goto cleanup;
            }
        }

        /* result */
        cat = cfg_getsec(rl, "result");
        if (cat) {
        }

        TAILQ_INSERT_TAIL(&((*xacml_policy)->xacml_rule_list), xacml_policy_rule, next);
    }


    cfg_free(cfg);
    return GA_GOOD;
cleanup:
    cfg_free(cfg);
    return GA_BAD;

}
