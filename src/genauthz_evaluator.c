#include "genauthz_evaluator.h"


evhtp_res
pdp_policy_evaluation(struct tq_xacml_request_s *xacml_req,
                      struct tq_xacml_response_s *xacml_res,
                      struct xacml_policy_s *xacml_policy) {
    evhtp_res http_res = EVHTP_RES_200;
    struct tq_xacml_category_s *category;
    struct tq_xacml_attribute_s *attribute, *new_attribute;

    if (xacml_req == NULL || xacml_res == NULL) {
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* First include all the attributes in the result based on their
     * IncludeInResult state */
    TAILQ_FOREACH(category, &(xacml_req->categories), next) {
        TAILQ_FOREACH(attribute, &(category->attributes), next) {
            if (attribute->include_in_result == GA_XACML_YES) {
                new_attribute = deep_copy_normalized_xacml_attribute(attribute);
                if (new_attribute == NULL) {
                    return EVHTP_RES_SERVERR;
                }
                TAILQ_INSERT_TAIL(&(xacml_res->attributes), new_attribute, next);
            }
        }
    }
    /* Print the normalized XACML Request & Response */
    print_normalized_xacml_request(xacml_req);
    print_normalized_xacml_response(xacml_res);

    /* TODO: The actual evaluation */
    print_loaded_policy(xacml_policy);

    http_res = EVHTP_RES_200;
final:
    return http_res;
}
