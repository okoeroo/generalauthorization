#include "genauthz_evaluator.h"


static enum answer_e
pdp_policy_find_matching_rule(struct tq_xacml_request_s *xacml_req,
                              struct tq_xacml_rule_s *rule) {
    struct tq_xacml_category_s *rule_cat, *req_cat;
    struct tq_xacml_attribute_s *rule_attr, *req_attr;
    struct tq_xacml_attribute_value_s *rule_value, *req_value;
    short found_cat = 0, found_attr = 0, found_value = 0, logical_AND_state = 0;

    if (!(TAILQ_EMPTY(&(rule->categories)))) {
        /* Match this category with the request */
        TAILQ_FOREACH(rule_cat, &(rule->categories), next) {
            /* Reset state */
            found_cat = 0;

            /* Example: Subject category in the rule */
            TAILQ_FOREACH(req_cat, &(xacml_req->categories), next) {
                /* Example: look for the Subject categroy in the request */
                if (rule_cat->type == req_cat->type) {
                    found_cat = 1;

                    /* When found, look in the Rule->Subject->Attributes */
                    TAILQ_FOREACH(rule_attr, &(rule_cat->attributes), next) {
                        /* Reset state */
                        found_attr = found_value = 0;
                        logical_AND_state = 0;

                        TAILQ_FOREACH(req_attr, &(req_cat->attributes), next) {
                            /* Match the Rule->Subject->subjectid with the same
                             * Request->Subject->subjectid */
                            if (strcasecmp((char *)rule_attr->id, (char *)req_attr->id) == 0) {
                                found_attr = 1;

                                /* Now look for the value(s), if set in the Rule to match */
                                if (TAILQ_EMPTY(&(req_attr->values))) {
                                    /* No specific value specified in the
                                     * policy, treat the existance of an
                                     * "AttributeId" in the request as a match */
                                     found_value = 1;
                                     break;
                                } else {
                                    TAILQ_FOREACH(rule_value, &(rule_attr->values), next) {
                                        TAILQ_FOREACH(req_value, &(req_attr->values), next) {
                                            /* check if the datatype matches */
                                            if (rule_value->datatype == req_value->datatype) {
                                                /* TODO: Casting! */
                                                if (strcmp((char *)rule_value->data, req_value->data) == 0) {
                                                    /* Got one! */
                                                    found_value = 1;
                                                    break;
                                                }
                                            }

                                        }
                                    }
                                }
                                /* When the AttributeId and the value are found and
                                 * the value too, check with the rule logic
                                 * setting. On a OR, we are now done and can return
                                 * from the function with success. If AND is set,
                                 * we need to walk all the categories and
                                 * AttributeIds with values, each to be found in
                                 * the request for a Rule match */
                                /* Ignore the case when the AttributeId is
                                 * found, not the value doesn't match. There
                                 * couldn't be another AttributeId set with a
                                 * matching value, elsewhere in the list. */
                                if (found_attr && found_value) {
                                    if (rule->logical == GA_XACML_LOGICAL_OR) {
                                        return YES;
                                    } else if (rule->logical == GA_XACML_LOGICAL_NOT) {
                                        return NO;
                                    } else if (rule->logical == GA_XACML_LOGICAL_AND) {
                                        logical_AND_state = 1;
                                        break;
                                    }
                                }
                            }
                        }
                        if (logical_AND_state) {
                            /* continue the rule */
                            continue;
                        } else {
                            /* AttributeId not found when the rule is a logical AND */
                            return NO;
                        }
                    }
                }
            }
            /* Category described in the rule, but not found in the request -> Failure */
            if (!found_cat) {
                return NO;
            }
        }
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

    return GA_GOOD;
}

static int
pdp_policy_evaluator(struct tq_xacml_request_s *xacml_req,
                     struct tq_xacml_response_s *xacml_res,
                     struct xacml_policy_s *xacml_policy) {
    struct tq_xacml_rule_s *rule;

    /* Find the first matching rule */
    TAILQ_FOREACH(rule, &(xacml_policy->xacml_rule_list), next) {
        if (pdp_policy_find_matching_rule(xacml_req, rule) == YES) {
            /* Rule matches, extract the decision and replicate it into the
             * XACML Response */
             if (pdp_policy_enforcer(xacml_req, xacml_res, rule) == GA_BAD) {
                 return GA_BAD;
             }
             break;
        }
    }

    return GA_GOOD;
}


evhtp_res
pdp_policy_evaluation(struct tq_xacml_request_s *xacml_req,
                      struct tq_xacml_response_s *xacml_res,
                      struct xacml_policy_s *xacml_policy) {
    evhtp_res http_res = EVHTP_RES_200;

    if (xacml_req == NULL || xacml_res == NULL || xacml_policy == NULL) {
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* The evaluation, could become a callback in the future */
    if (GA_GOOD != pdp_policy_evaluator(xacml_req,
                                        xacml_res,
                                        xacml_policy)) {
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    http_res = EVHTP_RES_200;
final:
    return http_res;
}
