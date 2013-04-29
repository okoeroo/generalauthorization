#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>

#include <string.h>

#include "queue.h"
#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_pdp.h"
#include "genauthz_xacml.h"
#include "genauthz_normalized_xacml.h"


const char *
xacml_decision2str(enum ga_xacml_decision_e desc) {
    switch (desc) {
        case GA_XACML_DECISION_PERMIT:
            return "Permit";
        case GA_XACML_DECISION_DENY:
            return "Deny";
        case GA_XACML_DECISION_NOTAPPLICABLE:
            return "NotApplicable";
        case GA_XACML_DECISION_INDETERMINATE:
        default:
            return "Indeterminate";
    }
    return "Indeterminate";
}


const char *
xacml_category_type2str(enum ga_xacml_category_e type) {
    switch (type) {
        case GA_XACML_CATEGORY_ENVIRONMENT:
            return "environment";
        case GA_XACML_CATEGORY_SUBJECT:
            return "subject";
        case GA_XACML_CATEGORY_ACTION:
            return "action";
        case GA_XACML_CATEGORY_RESOURCE:
            return "resource";
        case GA_XACML_CATEGORY_UNKNOWN:
        default:
            return "unknown";
    }
    return "unknown";
}

void
print_normalized_xacml_response(struct tq_xacml_response_s *response) {
    struct tq_xacml_category_s *category;
    struct tq_xacml_attribute_s *attribute;
    struct tq_xacml_attribute_value_s *value;

    printf("= XACML Response NS: %s =\n", response->ns);
    TAILQ_FOREACH(category, &(response->obligations), next) {
        printf(" Obligation ID: %s\n", category->id);
        printf(" Category type: %s\n", xacml_category_type2str(category->type));
        TAILQ_FOREACH(attribute, &(category->attributes), next) {
            printf("  Attribute ID: %s\n", attribute->id);
            printf("  Attribute IncludeInResult: %s\n",
                   attribute->include_in_result == GA_XACML_NO ? "No" : "Yes");
            TAILQ_FOREACH(value, &(attribute->values), next) {
                printf("   Datatype ID: %s\n", value->datatype_id);
                if (value->datatype == GA_XACML_DATATYPE_STRING) {
                    printf("   Data: \"%s\"\n", (char *)value->data);
                }
            }
        }
    }
    TAILQ_FOREACH(category, &(response->advices), next) {
        printf(" Advice ID: %s\n", category->id);
        printf(" Category type: %s\n", xacml_category_type2str(category->type));
        TAILQ_FOREACH(attribute, &(category->attributes), next) {
            printf("  Attribute ID: %s\n", attribute->id);
            printf("  Attribute IncludeInResult: %s\n",
                   attribute->include_in_result == GA_XACML_NO ? "No" : "Yes");
            TAILQ_FOREACH(value, &(attribute->values), next) {
                printf("   Datatype ID: %s\n", value->datatype_id);
                if (value->datatype == GA_XACML_DATATYPE_STRING) {
                    printf("   Data: \"%s\"\n", (char *)value->data);
                }
            }
        }
    }
    TAILQ_FOREACH(attribute, &(response->attributes), next) {
        printf("  Attribute ID: %s\n", attribute->id);
        printf("  Attribute IncludeInResult: %s\n",
               attribute->include_in_result == GA_XACML_NO ? "No" : "Yes");
        TAILQ_FOREACH(value, &(attribute->values), next) {
            printf("   Datatype ID: %s\n", value->datatype_id);
            if (value->datatype == GA_XACML_DATATYPE_STRING) {
                printf("   Data: \"%s\"\n", (char *)value->data);
            }
        }
    }
    return;
}

void
print_normalized_xacml_request(struct tq_xacml_request_s *request) {
    struct tq_xacml_category_s *category;
    struct tq_xacml_attribute_s *attribute;
    struct tq_xacml_attribute_value_s *value;

    printf("= XACML Request NS: %s =\n", request->ns);
    TAILQ_FOREACH(category, &(request->categories), next) {
        printf(" Category ID: %s\n", category->id);
        printf(" Category type: %s\n", xacml_category_type2str(category->type));
        TAILQ_FOREACH(attribute, &(category->attributes), next) {
            printf("  Attribute ID: %s\n", attribute->id);
            printf("  Attribute IncludeInResult: %s\n",
                   attribute->include_in_result == GA_XACML_NO ? "No" : "Yes");
            TAILQ_FOREACH(value, (&(attribute->values)), next) {
                printf("   Datatype ID: %s\n", value->datatype_id);
                if (value->datatype == GA_XACML_DATATYPE_STRING) {
                    printf("   Data: \"%s\"\n", (char *)value->data);
                }
            }
        }
    }
    return;
}

void
delete_normalized_xacml_attribute_value(struct tq_xacml_attribute_value_s *value) {
    if (value == NULL)
        return;

    /* TODO: Think of possible casting of native datatypes */
    free(value->data);
    free(value->datatype_id);
    memset(value, 0, sizeof(struct tq_xacml_attribute_value_s));
    return;
}

void
delete_normalized_xacml_attribute(struct tq_xacml_attribute_s *attribute) {
    struct tq_xacml_attribute_value_s *value, *value_tmp;

    if (attribute == NULL)
        return;

    free(attribute->id);

    TAILQ_FOREACH_SAFE(value, &attribute->values, next, value_tmp) {
        TAILQ_REMOVE(&(attribute->values), value, next);
        delete_normalized_xacml_attribute_value(value);
        free(value);
    }
    memset(attribute, 0, sizeof(struct tq_xacml_attribute_s));
    return;
}

void
delete_normalized_xacml_category(struct tq_xacml_category_s *category) {
    struct tq_xacml_attribute_s *attribute, *attribute_tmp;

    if (category == NULL)
        return;

    free(category->id);

    TAILQ_FOREACH_SAFE(attribute, &category->attributes, next, attribute_tmp) {
        TAILQ_REMOVE(&(category->attributes), attribute, next);
        delete_normalized_xacml_attribute(attribute);
        free(attribute);
    }
    memset(category, 0, sizeof(struct tq_xacml_category_s));
    return;
}

void
delete_normalized_xacml_response(struct tq_xacml_response_s *response) {
    struct tq_xacml_category_s *obligation, *obligation_tmp;
    struct tq_xacml_category_s *advice, *advice_tmp;
    struct tq_xacml_attribute_s *attribute, *attribute_tmp;

    if (response == NULL)
        return;

    free(response->ns);
    TAILQ_FOREACH_SAFE(obligation, &response->obligations, next, obligation_tmp) {
        TAILQ_REMOVE(&response->obligations, obligation, next);
        delete_normalized_xacml_category(obligation);
        free(obligation);
    }
    TAILQ_FOREACH_SAFE(advice, &response->advices, next, advice_tmp) {
        TAILQ_REMOVE(&response->advices, advice, next);
        delete_normalized_xacml_category(advice);
        free(advice);
    }
    TAILQ_FOREACH_SAFE(attribute, &response->attributes, next, attribute_tmp) {
        TAILQ_REMOVE(&response->attributes, attribute, next);
        delete_normalized_xacml_attribute(attribute);
        free(attribute);
    }
    free(response);
    return;
}

void
delete_normalized_xacml_request(struct tq_xacml_request_s *request) {
    struct tq_xacml_category_s *category;
    struct tq_xacml_category_s *category_tmp;

    if (request == NULL)
        return;

    free(request->ns);
    TAILQ_FOREACH_SAFE(category, &request->categories, next, category_tmp) {
        TAILQ_REMOVE(&request->categories, category, next);
        delete_normalized_xacml_category(category);
        free(category);
    }
    memset(request, 0, sizeof(struct tq_xacml_request_s));
    free(request);
    return;
}

struct tq_xacml_response_s *
create_normalized_xacml_response(void) {
    struct tq_xacml_response_s *xacml_res;

    /* Construct response */
    xacml_res = malloc(sizeof(struct tq_xacml_response_s));
    if (xacml_res == NULL) {
        goto final;
    }

    /* Set namespace to XACML 3.0 */
    xacml_res->ns = (unsigned char *)strdup("urn:oasis:names:tc:xacml:3.0:core:schema:wd-17");
    if (xacml_res->ns == NULL) {
        free(xacml_res);
        xacml_res = NULL;
        goto final;
    }
    TAILQ_INIT(&(xacml_res->obligations));
    TAILQ_INIT(&(xacml_res->advices));
    TAILQ_INIT(&(xacml_res->attributes));

final:
    return xacml_res;
}

struct tq_xacml_attribute_value_s *
create_normalized_xacml_attribute_value(void) {
    struct tq_xacml_attribute_value_s *attribute_value;

    attribute_value = malloc(sizeof(struct tq_xacml_attribute_value_s));
    if (attribute_value == NULL)
        return NULL;
    memset(attribute_value, 0, sizeof(struct tq_xacml_attribute_value_s));

    return attribute_value;
}

struct tq_xacml_attribute_s *
create_normalized_xacml_attribute(void) {
    struct tq_xacml_attribute_s *attribute;

    attribute = malloc(sizeof(struct tq_xacml_attribute_s));
    if (attribute == NULL)
        return NULL;
    memset(attribute, 0, sizeof(struct tq_xacml_attribute_s));
    TAILQ_INIT(&(attribute->values));

    return attribute;
}

struct tq_xacml_category_s *
create_normalized_xacml_category(void) {
    struct tq_xacml_category_s *category;

    category = malloc(sizeof(struct tq_xacml_category_s));
    if (category == NULL)
        return NULL;
    memset(category, 0, sizeof(struct tq_xacml_category_s));
    category->type = GA_XACML_CATEGORY_UNDEFINED;
    TAILQ_INIT(&(category->attributes));

    return category;
}

struct tq_xacml_attribute_value_s *
deep_copy_normalized_xacml_attribute_value(struct tq_xacml_attribute_value_s *original) {
    struct tq_xacml_attribute_value_s *dcopy;

    if (original == NULL)
        return NULL;

    dcopy = create_normalized_xacml_attribute_value();
    if (dcopy == NULL)
        return NULL;

    dcopy->datatype_id = (unsigned char *)strdup((char *)original->datatype_id);
    if (dcopy->datatype_id == NULL) {
        delete_normalized_xacml_attribute_value(dcopy);
        return NULL;
    }
    dcopy->datatype = original->datatype;
    /* TODO: Take care of casting! */
    dcopy->data = strdup(original->data);
    if (dcopy->data == NULL) {
        delete_normalized_xacml_attribute_value(dcopy);
        return NULL;
    }
    return dcopy;
}

struct tq_xacml_attribute_s *
deep_copy_normalized_xacml_attribute(struct tq_xacml_attribute_s *original) {
    struct tq_xacml_attribute_s *dcopy;
    struct tq_xacml_attribute_value_s *value, *new_value;

    if (original == NULL)
        return NULL;

    dcopy = create_normalized_xacml_attribute();
    if (dcopy == NULL)
        return NULL;
    dcopy->id = (unsigned char *)strdup((char *)original->id);
    if (dcopy->id == NULL) {
        delete_normalized_xacml_attribute(dcopy);
        return NULL;
    }
    dcopy->include_in_result = original->include_in_result;

    TAILQ_FOREACH(value, &(original->values), next) {
        new_value = deep_copy_normalized_xacml_attribute_value(value);
        if (new_value == NULL) {
            delete_normalized_xacml_attribute(dcopy);
            return NULL;
        }
        TAILQ_INSERT_TAIL(&(dcopy->values), new_value, next);
    }
    return dcopy;
}

evhtp_res
pdp_policy_evaluation(struct tq_xacml_request_s *xacml_req,
                      struct tq_xacml_response_s *xacml_res) {
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

    http_res = EVHTP_RES_200;
final:
    return http_res;
}
