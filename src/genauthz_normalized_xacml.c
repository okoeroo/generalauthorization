#include "ga_config.h"
#include "genauthz/genauthz_normalized_xacml.h"


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
            return "Environment";
        case GA_XACML_CATEGORY_SUBJECT:
            return "Subject";
        case GA_XACML_CATEGORY_ACTION:
            return "Action";
        case GA_XACML_CATEGORY_RESOURCE:
            return "Resource";
        case GA_XACML_CATEGORY_OBLIGATION:
            return "Obligation";
        case GA_XACML_CATEGORY_ADVICE:
            return "Advice";
        case GA_XACML_CATEGORY_UNDEFINED:
            return "Undefined";
        case GA_XACML_CATEGORY_UNKNOWN:
        default:
            return "unknown";
    }
    return "unknown";
}

void
print_normalized_xacml_response(struct tq_xacml_response_s *response) {
    struct tq_xacml_category_s *x_category;
    struct tq_xacml_attribute_s *x_attribute;
    struct tq_xacml_attribute_value_s *x_value;

    if (!response) return;

    printf("= XACML Response NS: %s =\n", response->ns);
    TAILQ_FOREACH(x_category, &(response->obligations), next) {
        printf(" Obligation ID: %s\n", x_category->id);
        printf(" Category type: %s\n", xacml_category_type2str(x_category->type));
        TAILQ_FOREACH(x_attribute, &(x_category->attributes), next) {
            printf("  Attribute ID: %s\n", x_attribute->id);
            printf("  Attribute IncludeInResult: %s\n",
                   x_attribute->include_in_result == GA_XACML_NO ? "No" : "Yes");
            TAILQ_FOREACH(x_value, &(x_attribute->values), next) {
                printf("   Datatype ID: %s\n", x_value->datatype_id);
                if (x_value->datatype == GA_XACML_DATATYPE_STRING) {
                    printf("   Data: \"%s\"\n", (char *)x_value->data);
                }
            }
        }
    }
    TAILQ_FOREACH(x_category, &(response->advices), next) {
        printf(" Advice ID: %s\n", x_category->id);
        printf(" Category type: %s\n", xacml_category_type2str(x_category->type));
        TAILQ_FOREACH(x_attribute, &(x_category->attributes), next) {
            printf("  Attribute ID: %s\n", x_attribute->id);
            printf("  Attribute IncludeInResult: %s\n",
                   x_attribute->include_in_result == GA_XACML_NO ? "No" : "Yes");
            TAILQ_FOREACH(x_value, &(x_attribute->values), next) {
                printf("   Datatype ID: %s\n", x_value->datatype_id);
                if (x_value->datatype == GA_XACML_DATATYPE_STRING) {
                    printf("   Data: \"%s\"\n", (char *)x_value->data);
                }
            }
        }
    }
    TAILQ_FOREACH(x_attribute, &(response->attributes), next) {
        printf("  Attribute ID: %s\n", x_attribute->id);
        printf("  Attribute IncludeInResult: %s\n",
               x_attribute->include_in_result == GA_XACML_NO ? "No" : "Yes");
        TAILQ_FOREACH(x_value, &(x_attribute->values), next) {
            printf("   Datatype ID: %s\n", x_value->datatype_id);
            if (x_value->datatype == GA_XACML_DATATYPE_STRING) {
                printf("   Data: \"%s\"\n", (char *)x_value->data);
            }
        }
    }
    return;
}

void
print_normalized_xacml_request(struct tq_xacml_request_s *request) {
    struct tq_xacml_category_s *x_category;
    struct tq_xacml_attribute_s *x_attribute;
    struct tq_xacml_attribute_value_s *x_value;

    if (!request) return;

    printf("= XACML Request NS: %s =\n", request->ns);
    TAILQ_FOREACH(x_category, &(request->categories), next) {
        printf(" Category ID: %s\n", x_category->id);
        printf(" Category type: %s\n", xacml_category_type2str(x_category->type));
        TAILQ_FOREACH(x_attribute, &(x_category->attributes), next) {
            printf("  Attribute ID: %s\n", x_attribute->id);
            printf("  Attribute IncludeInResult: %s\n",
                   x_attribute->include_in_result == GA_XACML_NO ? "No" : "Yes");
            TAILQ_FOREACH(x_value, (&(x_attribute->values)), next) {
                printf("   Datatype ID: %s\n", x_value->datatype_id);
                if (x_value->datatype == GA_XACML_DATATYPE_STRING) {
                    printf("   Data: \"%s\"\n", (char *)x_value->data);
                }
            }
        }
    }
    return;
}

void
delete_normalized_xacml_attribute_value(struct tq_xacml_attribute_value_s *x_value) {
    if (!x_value) return;

    /* TODO: Think of possible casting of native datatypes */
    free(x_value->data);
    free(x_value->datatype_id);
    memset(x_value, 0, sizeof(struct tq_xacml_attribute_value_s));
    return;
}

void
delete_normalized_xacml_attribute(struct tq_xacml_attribute_s *x_attribute) {
    struct tq_xacml_attribute_value_s *x_value, *x_value_tmp;

    if (!x_attribute) return;

    free(x_attribute->id);

    TAILQ_FOREACH_SAFE(x_value, &x_attribute->values, next, x_value_tmp) {
        TAILQ_REMOVE(&(x_attribute->values), x_value, next);
        delete_normalized_xacml_attribute_value(x_value);
        free(x_value);
    }
    memset(x_attribute, 0, sizeof(struct tq_xacml_attribute_s));
    return;
}

void
delete_normalized_xacml_category(struct tq_xacml_category_s *x_category) {
    struct tq_xacml_attribute_s *x_attribute, *x_attribute_tmp;

    if (!x_category) return;

    free(x_category->id);

    TAILQ_FOREACH_SAFE(x_attribute, &x_category->attributes, next, x_attribute_tmp) {
        TAILQ_REMOVE(&(x_category->attributes), x_attribute, next);
        delete_normalized_xacml_attribute(x_attribute);
        free(x_attribute);
    }
    memset(x_category, 0, sizeof(struct tq_xacml_category_s));
    return;
}

void
delete_normalized_xacml_response(struct tq_xacml_response_s *response) {
    struct tq_xacml_category_s *obligation, *obligation_tmp;
    struct tq_xacml_category_s *advice, *advice_tmp;
    struct tq_xacml_attribute_s *x_attribute, *x_attribute_tmp;

    if (!response) return;

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
    TAILQ_FOREACH_SAFE(x_attribute, &response->attributes, next, x_attribute_tmp) {
        TAILQ_REMOVE(&response->attributes, x_attribute, next);
        delete_normalized_xacml_attribute(x_attribute);
        free(x_attribute);
    }
    free(response);
    return;
}

void
delete_normalized_xacml_request(struct tq_xacml_request_s *request) {
    struct tq_xacml_category_s *category;
    struct tq_xacml_category_s *category_tmp;

    if (!request) return;

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

struct tq_xacml_request_s *
create_normalized_xacml_request(void) {
    struct tq_xacml_request_s *xacml_req;

    /* Construct request */
    xacml_req = malloc(sizeof(struct tq_xacml_request_s));
    if (!xacml_req) goto final;

    /* Set namespace to XACML 3.0 */
    xacml_req->ns = NULL;
    TAILQ_INIT(&(xacml_req->categories));

final:
    return xacml_req;
}

struct tq_xacml_response_s *
create_normalized_xacml_response(void) {
    struct tq_xacml_response_s *xacml_res;

    /* Construct response */
    xacml_res = malloc(sizeof(struct tq_xacml_response_s));
    if (!xacml_res) goto final;

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
    if (!attribute_value) return NULL;

    memset(attribute_value, 0, sizeof(struct tq_xacml_attribute_value_s));
    attribute_value->datatype = GA_XACML_DATATYPE_STRING;

    return attribute_value;
}

struct tq_xacml_attribute_s *
create_normalized_xacml_attribute(void) {
    struct tq_xacml_attribute_s *x_attribute;

    x_attribute = malloc(sizeof(struct tq_xacml_attribute_s));
    if (!x_attribute) return NULL;

    memset(x_attribute, 0, sizeof(struct tq_xacml_attribute_s));
    x_attribute->include_in_result = GA_XACML_NO;
    TAILQ_INIT(&(x_attribute->values));

    return x_attribute;
}

struct tq_xacml_category_s *
create_normalized_xacml_category(void) {
    struct tq_xacml_category_s *category;

    category = malloc(sizeof(struct tq_xacml_category_s));
    if (!category) return NULL;

    memset(category, 0, sizeof(struct tq_xacml_category_s));
    category->type = GA_XACML_CATEGORY_UNDEFINED;
    TAILQ_INIT(&(category->attributes));

    return category;
}

struct tq_xacml_attribute_value_s *
deep_copy_normalized_xacml_attribute_value(struct tq_xacml_attribute_value_s *original) {
    struct tq_xacml_attribute_value_s *dcopy;

    if (!original) return NULL;

    dcopy = create_normalized_xacml_attribute_value();
    if (!dcopy) return NULL;

    if (original->datatype_id) {
        dcopy->datatype_id = (unsigned char *)strdup((char *)original->datatype_id);
        if (dcopy->datatype_id == NULL) {
            delete_normalized_xacml_attribute_value(dcopy);
            return NULL;
        }
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

    if (!original) return NULL;

    dcopy = create_normalized_xacml_attribute();
    if (!dcopy) return NULL;

    if (original->id) {
        dcopy->id = (unsigned char *)strdup((char *)original->id);
        if (dcopy->id == NULL) {
            delete_normalized_xacml_attribute(dcopy);
            return NULL;
        }
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

struct tq_xacml_category_s *
deep_copy_normalized_xacml_category(struct tq_xacml_category_s *original) {
    struct tq_xacml_category_s *dcopy;
    struct tq_xacml_attribute_s *attr, *new_attr;

    if (!original) return NULL;

    dcopy = create_normalized_xacml_category();
    if (!dcopy) return NULL;

    dcopy->type = original->type;
    if (original->id) {
        dcopy->id = (unsigned char *)strdup((char *)original->id);
        if (dcopy->id == NULL) {
            delete_normalized_xacml_category(dcopy);
            return NULL;
        }
    } else {
        dcopy->id = NULL;
    }

    TAILQ_FOREACH(attr, &(original->attributes), next) {
        new_attr = deep_copy_normalized_xacml_attribute(attr);

        if (new_attr == NULL) {
            delete_normalized_xacml_category(dcopy);
            return NULL;
        }
        TAILQ_INSERT_TAIL(&(dcopy->attributes), new_attr, next);
    }
    return dcopy;
}


