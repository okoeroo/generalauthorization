#include "ga_config.h"
#include "genauthz/genauthz_evaluator.h"

static enum answer_e
pdp_policy_find_matching_attribute(struct tq_xacml_rule_s *rule,
                                   struct tq_xacml_attribute_s *rule_attr,
                                   struct tq_xacml_attribute_s *req_attr) {
    struct tq_xacml_attribute_value_s *rule_value, *req_value;
    short found_value = 0, logical_AND_state = 1;
    short logical_OR_state = 0;

    if (TAILQ_EMPTY(&(rule_attr->values))) {
        return YES;
    } else if (TAILQ_EMPTY(&(req_attr->values))) {
        return NO;
    }

    TAILQ_FOREACH(rule_value, &(rule_attr->values), next) {
        TAILQ_FOREACH(req_value, &(req_attr->values), next) {
            /* check if the datatype matches */
            if (rule_value->datatype == req_value->datatype) {
                /* TODO: Casting! */
                if (strcmp((char *)rule_value->data, req_value->data) == 0) {
                    /* Got one! */
                    logical_OR_state = found_value = 1;
                    break;
                }
            }
        }

        if (!found_value && rule->logical == GA_XACML_LOGICAL_AND) {
            return NO;
        } else if (found_value && rule->logical == GA_XACML_LOGICAL_NOT) {
            return NO;
        } /* Left over is the OR logic, which evaluates later */

        if (!found_value) {
            logical_AND_state = 0;
        }
    }

    if (logical_OR_state && rule->logical == GA_XACML_LOGICAL_OR) {
        return YES;
    }
    if (logical_AND_state && rule->logical == GA_XACML_LOGICAL_AND) {
        return YES;
    }

    /* All is negative, could still be a NOT operator */
    if (rule->logical == GA_XACML_LOGICAL_NOT) {
        return YES;
    }

    return NO;
}

static enum answer_e
pdp_policy_find_matching_category(struct tq_xacml_rule_s *rule,
                                  struct tq_xacml_category_s *rule_cat,
                                  struct tq_xacml_category_s *req_cat) {
    struct tq_xacml_attribute_s *rule_attr, *req_attr;
    short found_attr = 0, logical_AND_state = 1;
    enum answer_e rc = NO;
    short logical_OR_state = 0;

    if (TAILQ_EMPTY(&(rule_cat->attributes))) {
        return YES;
    } else if (TAILQ_EMPTY(&(req_cat->attributes))) {
        return NO;
    }

    TAILQ_FOREACH(rule_attr, &(rule_cat->attributes), next) {
        found_attr = 0;
        TAILQ_FOREACH(req_attr, &(req_cat->attributes), next) {
            if (strcasecmp((char *)rule_attr->id, (char *)req_attr->id) == 0) {
                found_attr = 1;
                break;
            }
        }
        if (!found_attr && rule->logical == GA_XACML_LOGICAL_AND) {
            return NO;
        } else if (found_attr && rule->logical == GA_XACML_LOGICAL_NOT) {
            return NO;
        } /* Left over is the OR logic, which evaluates later */

        if (!found_attr) {
            logical_AND_state = 0;
            continue;
        }

        rc = pdp_policy_find_matching_attribute(rule, rule_attr, req_attr);
        if (rc == YES && rule->logical == GA_XACML_LOGICAL_OR) {
            return YES;
        } else if (rc == NO && rule->logical == GA_XACML_LOGICAL_AND) {
            return NO;
        }
    }

    if (logical_OR_state && (rule->logical == GA_XACML_LOGICAL_OR)) {
        return YES;
    }
    if (logical_AND_state && (rule->logical == GA_XACML_LOGICAL_AND)) {
        return YES;
    }

    /* All is negative, could still be a NOT operator */
    if (rule->logical == GA_XACML_LOGICAL_NOT) {
        return YES;
    }

    return NO;
}


static enum answer_e
pdp_policy_find_matching_rule(struct tq_xacml_request_s *xacml_req,
                              struct tq_xacml_rule_s *rule) {
    struct tq_xacml_category_s *rule_cat, *req_cat;
    short found_cat = 0;
    enum answer_e rc = NO;
    short logical_OR_state = 0, logical_AND_state = 1;

    if (TAILQ_EMPTY(&(rule->categories))) {
        return NO;
    }

    TAILQ_FOREACH(rule_cat, &(rule->categories), next) {
        TAILQ_FOREACH(req_cat, &(xacml_req->categories), next) {
            if (rule_cat->type == req_cat->type) {
                logical_OR_state = found_cat = 1;
                break;
            }
        }
        if (!found_cat && rule->logical == GA_XACML_LOGICAL_AND) {
            return NO;
        } else if (found_cat && rule->logical == GA_XACML_LOGICAL_NOT) {
            return NO;
        } /* Left over is the OR logic, which evaluates later */

        if (!found_cat) {
            logical_AND_state = 0;
            continue;
        }

        rc = pdp_policy_find_matching_category(rule, rule_cat, req_cat);
        if (rc == YES && rule->logical == GA_XACML_LOGICAL_OR) {
            return YES;
        } else if (rc == NO && rule->logical == GA_XACML_LOGICAL_AND) {
            return NO;
        }
    }

    if (logical_OR_state && rule->logical == GA_XACML_LOGICAL_OR) {
        return YES;
    }
    if (logical_AND_state && rule->logical == GA_XACML_LOGICAL_AND) {
        return YES;
    }

    /* All is negative, could still be a NOT operator */
    if (rule->logical == GA_XACML_LOGICAL_NOT) {
        return YES;
    }

    return NO;
}


static int
pdp_policy_enforcer(struct tq_xacml_request_s *xacml_req,
                    struct tq_xacml_response_s *xacml_res,
                    struct tq_xacml_rule_s *rule) {
    struct tq_xacml_category_s *cat, *tmp_cat;
    struct tq_xacml_attribute_s *attribute, *new_attribute;

    if (rule->decision) {
        TAILQ_FOREACH(cat, &(rule->decision->obligations), next) {
            tmp_cat = deep_copy_normalized_xacml_category(cat);
            if (!tmp_cat) {
                return GA_BAD;
            }
            TAILQ_INSERT_TAIL(&(xacml_res->obligations), tmp_cat, next);
        }
        TAILQ_FOREACH(cat, &(rule->decision->advices), next) {
            tmp_cat = deep_copy_normalized_xacml_category(cat);
            if (!tmp_cat) {
                return GA_BAD;
            }
            TAILQ_INSERT_TAIL(&(xacml_res->advices), tmp_cat, next);
        }

        /* Transfer the actual decision */
        xacml_res->decision = rule->decision->decision;
    }

    /* include all the attributes in the result based on their IncludeInResult
     * state */
    TAILQ_FOREACH(cat, &(xacml_req->categories), next) {
        TAILQ_FOREACH(attribute, &(cat->attributes), next) {
            if (attribute->include_in_result == GA_XACML_YES) {
                new_attribute = deep_copy_normalized_xacml_attribute(attribute);
                if (new_attribute == NULL) {
                    return GA_BAD;
                }
                TAILQ_INSERT_TAIL(&(xacml_res->attributes), new_attribute, next);
            }
        }
    }

    /* Rule call-counter */
    rule->rule_call_count++;

    return GA_GOOD;
}


/* Function: pdp_policy_evaluator()
 * GA_GOOD means: Evaluation was a success, decision could be Deny,
 *                Allow, NotApplicable or Indeterminate.
 * GA_BAD means:  The evaluation process has internally failed.  Example: The
 *                plugin call-out failed for some reason, regardless of its
 *                semantic results
 */
static int
pdp_policy_evaluator(request_mngr_t *request_mngr) {
    struct tq_xacml_rule_s *rule;

    /* Explicitly set the result to Indeterminate as a safe-guard */
    request_mngr->xacml_res->decision = GA_XACML_DECISION_INDETERMINATE;

    /* Find the first matching rule */
    TAILQ_FOREACH(rule, &(request_mngr->app->parent->xacml_policy->xacml_rule_list), next) {
        if (pdp_policy_find_matching_rule(request_mngr->xacml_req, rule) == YES) {
            /* Rule matches, extract the decision and replicate it into the
             * XACML Response */

            /* The enforcer will push the Rule's decision and static
             * obligations, advices and Include-in-Result attributes in the
             * normalized XACML Response structures */
            if (pdp_policy_enforcer(request_mngr->xacml_req,
                                    request_mngr->xacml_res,
                                    rule) == GA_BAD) {
                return GA_BAD; /* Internal server failure */
            }

            /* Run the callouts */
            if (genauthz_execute_rule_callouts(request_mngr, rule) == GA_BAD) {
                return GA_BAD; /* Internal server failure */
            }

            /* Rule hit, enforced by static policy and callout(s), now
               quickly back to the output functions and report to the user */
            break;
        }
    }
    return GA_GOOD;
}


evhtp_res
pdp_policy_evaluation(request_mngr_t *request_mngr) {
    evhtp_res http_res = EVHTP_RES_200;

    if (!request_mngr ||
        !request_mngr->xacml_req ||
        !request_mngr->xacml_res ||
        !request_mngr->app->parent->xacml_policy) {
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* The evaluation, could become a callback in the future */
    if (GA_GOOD != pdp_policy_evaluator(request_mngr)) {
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    http_res = EVHTP_RES_200;
final:
    return http_res;
}
