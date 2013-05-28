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
    else if(strcasecmp(value, "NAND") == 0)
        *(enum ga_xacml_logical_e *)result = GA_XACML_LOGICAL_NAND;
    else if(strcasecmp(value, "NOR") == 0)
        *(enum ga_xacml_logical_e *)result = GA_XACML_LOGICAL_NOR;
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

    if (cfg_getstr(attr, "attributeid")) {
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
rule_category_parser(struct tq_xacml_rule_s *rule,
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
        if (rule_attribute_parser(x_category->attributes, attr) == GA_BAD)
            goto cleanup;
    }

    /* Walk explicit attribute */
    if (cfg_getstr(cat, "attributeid") &&
        cfg_getstr(cat, "function") &&
        cfg_getstr(cat, "value")) {

        if (rule_attribute_parser(x_category->attributes, cat) == GA_BAD)
            goto cleanup;
    }

    TAILQ_INSERT_TAIL(&(rule->categories), x_category, next);

    return GA_GOOD;
cleanup:
    delete_normalized_xacml_category(x_category);
    return GA_BAD;
}


static int
rule_decision_category_parser(tq_xacml_category_list_t obligatory_advices,
                              enum ga_xacml_category_e cat_type,
                              cfg_t *cat) {
    /* Create category */
    struct tq_xacml_category_s *x_category = NULL;
    cfg_t *attr;
    int i, n_attr;

    x_category = create_normalized_xacml_category();
    if (x_category == NULL)
        return GA_BAD;
    x_category->type = cat_type;

    if (cat_type == GA_XACML_CATEGORY_OBLIGATION) {
        x_category->id = (unsigned char *)strdup(cfg_getstr(cat, "obligationid"));
    } else if (cat_type == GA_XACML_CATEGORY_ADVICE) {
        x_category->id = (unsigned char *)strdup(cfg_getstr(cat, "adviceid"));
    }

    /* Walk explicit attributes */
    n_attr = cfg_size(cat, "attribute");
    for (i = 0; i < n_attr; i++) {
        attr = cfg_getnsec(cat, "attribute", i);
        if (rule_attribute_parser(x_category->attributes, attr) == GA_BAD) {
            goto cleanup;
        }
    }

    TAILQ_INSERT_TAIL(&obligatory_advices, x_category, next);
    return GA_GOOD;
cleanup:
    delete_normalized_xacml_category(x_category);
    return GA_BAD;
}

static int
rule_callout_parser(struct tq_xacml_rule_s *rule,
                     cfg_t *callout_cfg) {
    struct tq_xacml_callout_s *callout;

    if (!callout_cfg)
        return GA_BAD;

    callout = malloc(sizeof(struct tq_xacml_callout_s));
    if (!callout)
        return GA_BAD;

    callout->plugin_path   = cfg_getstr(callout_cfg, "plugin")   ?
                                strdup(cfg_getstr(callout_cfg, "plugin")) : NULL;
    if (!callout->plugin_path)
        goto cleanup;

    callout->function_name = cfg_getstr(callout_cfg, "function") ?
                                strdup(cfg_getstr(callout_cfg, "function")) : NULL;
    if (!callout->function_name)
        goto cleanup;

    TAILQ_INSERT_TAIL(&(rule->callouts), callout, next);
    return GA_GOOD;
cleanup:
    /* delete callout struct */
    if (callout) {
        free(callout->plugin_path);
        free(callout->function_name);
        free(callout);
    }
    return GA_BAD;
}

static int
rule_decision_parser(struct tq_xacml_rule_s *rule,
                     cfg_t *result) {
    struct tq_xacml_decision_s *decision;
    int i, n_oblig, n_advice;
    cfg_t *cat;

    if (!result)
        return GA_BAD;

    decision = malloc(sizeof(struct tq_xacml_decision_s));
    if (decision == NULL)
        return GA_BAD;

    TAILQ_INIT(&(decision->obligations));
    TAILQ_INIT(&(decision->advices));

    decision->decision = cfg_getint(result, "decision");

    /* Obligations and Advices parsing */
    n_oblig = cfg_size(result, "obligation");
    for (i = 0; i < n_oblig; i++) {
        cat = cfg_getnsec(result, "obligation", i);
        if (GA_BAD == rule_decision_category_parser(decision->obligations,
                                                    GA_XACML_CATEGORY_OBLIGATION,
                                                    cat)) {
            goto cleanup;
        }
    }
    n_advice = cfg_size(result, "advice");
    for (i = 0; i < n_advice; i++) {
        cat = cfg_getnsec(result, "advice", i);
        if (GA_BAD == rule_decision_category_parser(decision->advices,
                                                    GA_XACML_CATEGORY_ADVICE,
                                                    cat)) {
            goto cleanup;
        }
    }

    rule->decision = decision;
    return GA_GOOD;
cleanup:
    /* delete decision struct */
    return GA_BAD;
}

static void
policy_rule_decision_attribute_value_2_evb(struct evbuffer *buffer,
                                           struct tq_xacml_attribute_value_s *value) {
    if (value->datatype_id) {
        evbuffer_add_printf(buffer, "        Datatype ID: %s\n", value->datatype_id);
    }
    if (value->datatype == GA_XACML_DATATYPE_STRING) {
        evbuffer_add_printf(buffer, "        Datatype: STRING\n");
        value->data ? evbuffer_add_printf(buffer, "        Data: \"%s\"\n", (char *)value->data)
                    : evbuffer_add_printf(buffer, "        Data: <empty>\n");
    } else {
        evbuffer_add_printf(buffer, "        Datatype: <other>\n");
        evbuffer_add_printf(buffer, "        Data: <can not display>\n");
    }

    return;
}

static void
policy_rule_decision_attribute_2_evb(struct evbuffer *buffer,
                                     struct tq_xacml_attribute_s *attr) {
    struct tq_xacml_attribute_value_s *value;
    evbuffer_add_printf(buffer, "      AttributeId: %s\n", attr->id);
    TAILQ_FOREACH(value, &(attr->values), next) {
        policy_rule_decision_attribute_value_2_evb(buffer, value);
    }
    return;
}

static void
category_2_evb(struct evbuffer *buffer,
               struct tq_xacml_category_s *cat) {
    struct tq_xacml_attribute_s *attr;

    if (cat->id)
        evbuffer_add_printf(buffer, "    %s: %s\n", xacml_category_type2str(cat->type), cat->id);
    else
        evbuffer_add_printf(buffer, "    %s\n", xacml_category_type2str(cat->type));

    TAILQ_FOREACH(attr, &(cat->attributes), next) {
        policy_rule_decision_attribute_2_evb(buffer, attr);
    }
    return;
}

static void
policy_rule_decision_2_evb(struct evbuffer *buffer,
                           struct tq_xacml_decision_s *decision) {
    struct tq_xacml_category_s *cat;

    switch(decision->decision) {
        case GA_XACML_DECISION_PERMIT:
            evbuffer_add_printf(buffer, "    Decision: Permit\n");
            break;
        case GA_XACML_DECISION_DENY:
            evbuffer_add_printf(buffer, "    Decision: Deny\n");
            break;
        case GA_XACML_DECISION_INDETERMINATE:
            evbuffer_add_printf(buffer, "    Decision: Intermediate\n");
            break;
        case GA_XACML_DECISION_NOTAPPLICABLE:
            evbuffer_add_printf(buffer, "    Decision: NotApplicable\n");
            break;
    }
    TAILQ_FOREACH(cat, &(decision->obligations), next) {
        category_2_evb(buffer, cat);
    }
    TAILQ_FOREACH(cat, &(decision->advices), next) {
        category_2_evb(buffer, cat);
    }

    return;
}

static void
policy_rule_2_evb(struct evbuffer *buffer,
                  struct tq_xacml_rule_s *rule) {
    struct tq_xacml_category_s *cat;

    if (!rule)
        return;

    if (rule->name)
        evbuffer_add_printf(buffer, "  Rule name: %s\n", rule->name);

    switch (rule->logical) {
        case GA_XACML_LOGICAL_AND:
            evbuffer_add_printf(buffer, "    logical: AND\n");
            break;
        case GA_XACML_LOGICAL_OR:
            evbuffer_add_printf(buffer, "    logical: OR\n");
            break;
        case GA_XACML_LOGICAL_NOT:
            evbuffer_add_printf(buffer, "    logical: NOT\n");
            break;
        case GA_XACML_LOGICAL_NAND:
            evbuffer_add_printf(buffer, "    logical: NAND\n");
            break;
        case GA_XACML_LOGICAL_NOR:
            evbuffer_add_printf(buffer, "    logical: NOR\n");
            break;
    }
    if (!(TAILQ_EMPTY(&(rule->categories)))) {
        TAILQ_FOREACH(cat, &(rule->categories), next) {
            category_2_evb(buffer, cat);
        }
    }
    if (rule->decision) {
        policy_rule_decision_2_evb(buffer, rule->decision);
    } else {
        evbuffer_add_printf(buffer, "    No decision set\n");
    }

    return;
}


void
policy_2_evb(struct evbuffer *buffer,
             struct xacml_policy_s *xacml_policy) {
    struct tq_xacml_rule_s *rule;

    evbuffer_add_printf(buffer, "= XACML Policy =\n");
    switch (xacml_policy->composition) {
        case GA_RULE_COMPOSITION_ANYOF:
            evbuffer_add_printf(buffer, "Composition: ANYOF\n");
            break;
        case GA_RULE_COMPOSITION_ALL:
            evbuffer_add_printf(buffer, "Composition: ALL\n");
            break;
        case GA_RULE_COMPOSITION_ONE:
            evbuffer_add_printf(buffer, "Composition: ONE\n");
            break;
    }

    TAILQ_FOREACH(rule, &(xacml_policy->xacml_rule_list), next) {
        policy_rule_2_evb(buffer, rule);
    }

}


void
print_loaded_policy(struct xacml_policy_s *xacml_policy) {
    struct evbuffer *buffer;

    if (!xacml_policy)
        return;

    buffer = evbuffer_new();
    if (!buffer)
        return;

    policy_2_evb(buffer, xacml_policy);
    printf("%s", evpull(buffer));
    evbuffer_free(buffer);

    return;
}

int
rule_parser(char *policy_file,
            struct xacml_policy_s **xacml_policy) {
    int ret, i, n_rules, n_rule;
    cfg_t *cfg, *cat;
    struct tq_xacml_rule_s *xacml_policy_rule;

    static cfg_opt_t attribute_opts[] = {
        CFG_STR("attributeid", 0, CFGF_NONE),
        CFG_STR("value", 0, CFGF_NONE),
        CFG_END()
    };
    static cfg_opt_t obligation_opts[] = {
        CFG_STR("obligationid", 0, CFGF_NONE),
        CFG_SEC("attribute", attribute_opts, CFGF_MULTI),
        CFG_END()
    };
    static cfg_opt_t advice_opts[] = {
        CFG_STR("adviceid", 0, CFGF_NONE),
        CFG_SEC("attribute", attribute_opts, CFGF_MULTI),
        CFG_END()
    };
    static cfg_opt_t result_opts[] = {
        CFG_INT_CB("decision", NONE, CFGF_NONE, &cb_rule_result_decision),
        CFG_SEC("obligation", obligation_opts, CFGF_MULTI),
        CFG_SEC("advice", advice_opts, CFGF_MULTI),
        CFG_END()
    };
    static cfg_opt_t callout_opts[] = {
        CFG_STR("plugin", 0, CFGF_NONE),
        CFG_STR("function", 0, CFGF_NONE),
        CFG_END()
    };
    static cfg_opt_t attribute_w_func_opts[] = {
        CFG_STR("attributeid", 0, CFGF_NONE),
        CFG_STR("function", 0, CFGF_NONE),
        CFG_STR("value", 0, CFGF_NONE),
        CFG_END()
    };
    static cfg_opt_t category_opts[] = {
        CFG_SEC("attribute", attribute_w_func_opts, CFGF_MULTI),
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
        CFG_SEC("callout", callout_opts, CFGF_MULTI),
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
        memset(xacml_policy_rule, 0, sizeof(struct tq_xacml_rule_s));

        /* TODO: Check if Rule Name is unique */
        xacml_policy_rule->name = strdup(cfg_title(rl));
        xacml_policy_rule->logical = cfg_getint(rl, "logical");
        TAILQ_INIT(&(xacml_policy_rule->categories));
        TAILQ_INIT(&(xacml_policy_rule->inherited_rules));
        TAILQ_INIT(&(xacml_policy_rule->callouts));
        xacml_policy_rule->decision = NULL;

        /* categories */
        cat = cfg_getsec(rl, "subject");
        if (cat) {
            if (rule_category_parser(xacml_policy_rule,
                                     cat,
                                     GA_XACML_CATEGORY_SUBJECT) == GA_BAD) {
                goto cleanup;
            }
        }
        cat = cfg_getsec(rl, "action");
        if (cat) {
            if (rule_category_parser(xacml_policy_rule,
                                     cat,
                                     GA_XACML_CATEGORY_ACTION) == GA_BAD) {
                goto cleanup;
            }
        }
        cat = cfg_getsec(rl, "resource");
        if (cat) {
            if (rule_category_parser(xacml_policy_rule,
                                     cat,
                                     GA_XACML_CATEGORY_RESOURCE) == GA_BAD) {
                goto cleanup;
            }
        }
        cat = cfg_getsec(rl, "environment");
        if (cat) {
            if (rule_category_parser(xacml_policy_rule,
                                     cat,
                                     GA_XACML_CATEGORY_ENVIRONMENT) == GA_BAD) {
                goto cleanup;
            }
        }

        /* result */
        cat = cfg_getsec(rl, "result");
        if (cat) {
            if (rule_decision_parser(xacml_policy_rule,
                                     cat) == GA_BAD) {
                goto cleanup;
            }
        }

        /* callout */
        cat = cfg_getsec(rl, "callout");
        if (cat) {
            if (rule_callout_parser(xacml_policy_rule,
                                    cat) == GA_BAD) {
                goto cleanup;
            }
        }

        TAILQ_INSERT_TAIL(&((*xacml_policy)->xacml_rule_list), xacml_policy_rule, next);
    }


    cfg_free(cfg);
    return GA_GOOD;
cleanup:
    cfg_free(cfg);
    return GA_BAD;

}
