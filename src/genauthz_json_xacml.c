#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>

#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_pdp.h"
#include "genauthz_xacml.h"
#include "genauthz_normalized_xacml.h"
#include "genauthz_json_xacml.h"

#include <string.h>
#include <jansson.h>

/*** Input processing ***/
static evhtp_res
normalize_json2xacml_attribute_values(struct tq_xacml_attribute_s *x_attribute,
                                      json_t *j_value) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    struct tq_xacml_attribute_value_s *x_value;
    size_t i;
    json_t *valval;

    x_value = create_normalized_xacml_attribute_value();
    if (!x_value) {
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    if (json_is_array(j_value)) {
        for (i = 0; i < json_array_size(j_value); i++) {
            valval = json_array_get(j_value, i);
            if (!valval)
                break;

            if (json_is_string(valval)) {
                x_value->datatype = GA_XACML_DATATYPE_STRING;
                x_value->data     = strdup(json_string_value(valval));
                if (!x_value->data) {
                    http_res = EVHTP_RES_SERVERR;
                    goto final;
                }
            } else if (json_is_integer(valval)) {
                x_value->datatype = GA_XACML_DATATYPE_INTEGER;
                x_value->data     = malloc(sizeof(json_int_t));
                if (!x_value->data) {
                    http_res = EVHTP_RES_SERVERR;
                    goto final;
                }
                x_value->data = (void *)json_integer_value(valval);
            }
            TAILQ_INSERT_TAIL(&(x_attribute->values), x_value, next);
        }
    } else if (json_is_string(j_value)) {
        x_value->datatype = GA_XACML_DATATYPE_STRING;
        x_value->data     = strdup(json_string_value(j_value));
        if (!x_value->data) {
            http_res = EVHTP_RES_SERVERR;
            goto final;
        }
        TAILQ_INSERT_TAIL(&(x_attribute->values), x_value, next);
    } else if (json_is_integer(j_value)) {
        x_value->datatype = GA_XACML_DATATYPE_INTEGER;
        x_value->data     = malloc(sizeof(json_int_t));
        if (!x_value->data) {
            http_res = EVHTP_RES_SERVERR;
            goto final;
        }
        x_value->data = (void *)json_integer_value(j_value);

        TAILQ_INSERT_TAIL(&(x_attribute->values), x_value, next);
    }

    http_res = EVHTP_RES_200;
final:
    return http_res;
}

static evhtp_res
normalize_json2xacml_attributes(struct tq_xacml_category_s *x_category,
                                json_t *j_attr_ar) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    json_t *attr, *attr_val;
    size_t i, sz;
    struct tq_xacml_attribute_s *x_attribute;

    sz = json_array_size(j_attr_ar);
    for (i = 0; i < sz; i++) {
        attr = json_array_get(j_attr_ar, i);
        if (!attr)
            break;

        attr_val = json_object_get(attr, "Id");

        x_attribute = create_normalized_xacml_attribute();
        if (!x_attribute) {
            http_res = EVHTP_RES_SERVERR;
            goto final;
        }
        x_attribute->id = (unsigned char *)strdup(json_string_value(attr_val));
        if (!x_attribute->id) {
            http_res = EVHTP_RES_SERVERR;
            goto final;
        }

        attr_val = json_object_get(attr, "Value");
        if (attr_val) {
            http_res = normalize_json2xacml_attribute_values(x_attribute, attr_val);
            if (http_res != EVHTP_RES_200) {
                goto final;
            }
        }

        TAILQ_INSERT_TAIL(&(x_category->attributes), x_attribute, next);
    }

    http_res = EVHTP_RES_200;
final:
    return http_res;
}


static evhtp_res
normalize_json2xacml_categories(struct tq_xacml_request_s *request,
                                json_t *j_cat,
                                enum ga_xacml_category_e cat_type) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    struct tq_xacml_category_s *category;
    json_t *j_attr_ar;

    category = create_normalized_xacml_category();
    if (category == NULL) {
        return EVHTP_RES_SERVERR;
    }
    category->type = cat_type;

    j_attr_ar = json_object_get(j_cat, "Attributes");
    http_res = normalize_json2xacml_attributes(category, j_attr_ar);
    if (http_res != EVHTP_RES_200) {
        goto final;
    }
    TAILQ_INSERT_TAIL(&(request->categories), category, next);

    http_res = EVHTP_RES_200;
final:
    return http_res;
}

static evhtp_res
normalize_json2xacml(struct tq_xacml_request_s *xacml_req,
                     json_t *doc) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    json_t *j_req, *j_cat;

    j_req = json_object_get(doc, "Request");
    if (!j_req) {
        http_res = EVHTP_RES_BADREQ;
        goto final;
    }

    j_cat = json_object_get(j_req, "Subject");
    if (j_cat) {
        http_res = normalize_json2xacml_categories(xacml_req,
                                                   j_cat,
                                                   GA_XACML_CATEGORY_SUBJECT);
        if (http_res != EVHTP_RES_200) {
            goto final;
        }
    }
    j_cat = json_object_get(j_req, "Action");
    if (j_cat) {
        http_res = normalize_json2xacml_categories(xacml_req,
                                                   j_cat,
                                                   GA_XACML_CATEGORY_ACTION);
        if (http_res != EVHTP_RES_200) {
            goto final;
        }
    }
    j_cat = json_object_get(j_req, "Resource");
    if (j_cat) {
        http_res = normalize_json2xacml_categories(xacml_req,
                                                   j_cat,
                                                   GA_XACML_CATEGORY_RESOURCE);
        if (http_res != EVHTP_RES_200) {
            goto final;
        }
    }
    j_cat = json_object_get(j_req, "Environment");
    if (j_cat) {
        http_res = normalize_json2xacml_categories(xacml_req,
                                                   j_cat,
                                                   GA_XACML_CATEGORY_ENVIRONMENT);
        if (http_res != EVHTP_RES_200) {
            goto final;
        }
    }


    http_res = EVHTP_RES_200;
final:
    return http_res;
}


evhtp_res
pdp_json_input_processor(struct tq_xacml_request_s **xacml_req,
                        evhtp_request_t *evhtp_req) {
    evhtp_res http_res = EVHTP_RES_SERVERR;
    json_t *doc;
    json_error_t j_error;

    doc = json_loadb((const char *)evpull(evhtp_req->buffer_in),
                     evbuffer_get_length(evhtp_req->buffer_in),
                     JSON_DISABLE_EOF_CHECK,
                     &j_error);
    if (doc == NULL) {
        http_res = EVHTP_RES_BADREQ;
        goto final;
    }


    /* Make me a request */
    *xacml_req = create_normalized_xacml_request();
    if (*xacml_req == NULL) {
        http_res = EVHTP_RES_SERVERR;
        goto final;
    }

    /* Normalize XACML Request */
    http_res = normalize_json2xacml(*xacml_req, doc);
    if (http_res != EVHTP_RES_200) {
        goto final;
    }

final:
    /* Free document */
    if (doc)
        json_decref(doc);

    return http_res;
}



/*** Output processing ***/

static int
normalized_xacml_attribute_values2json_evbuffer(struct evbuffer *output,
                                                tq_xacml_attribute_value_list_t attr_value_list) {
    struct tq_xacml_attribute_value_s *value;
    int    first;
    int    c;

    TAILQ_COUNT_SAFE(c, value, &attr_value_list, next);

    if (c == 0) {
        return 0;
    } else if (c == 1) {
        TAILQ_FOREACH(value, &attr_value_list, next) {
            if (value->datatype == GA_XACML_DATATYPE_STRING) {
                evbuffer_add_printf(output, "            \"Value\": \"%s\"",
                                            (char *)value->data);
            } else if (value->datatype == GA_XACML_DATATYPE_INTEGER) {
                evbuffer_add_printf(output, "            \"Value\": %d",
                                            (int32_t)value->data);
            }
        }
    } else {
        evbuffer_add_printf(output, "            \"Value\": [");

        first = 1;
        TAILQ_FOREACH(value, &attr_value_list, next) {
            first ? first = 0 : evbuffer_add_printf(output, ",");

            if (value->datatype == GA_XACML_DATATYPE_STRING) {
                evbuffer_add_printf(output, "\"%s\"",
                                            (char *)value->data);
            } else if (value->datatype == GA_XACML_DATATYPE_INTEGER) {
                evbuffer_add_printf(output, "%d",
                                            (int32_t)value->data);
            }
        }
        evbuffer_add_printf(output, "]");
    }

    return 0;
}

static int
normalized_xacml_attributes2json_evbuffer(struct evbuffer *output,
                                          tq_xacml_attribute_list_t attr_list) {
    struct tq_xacml_attribute_s *x_attribute;
    int    first = 1;
    int    c;

    /*

        "Attribute": [{
                    "Id": "urn:oasis:names:tc:xacml:2.0:subject:role",
                    "Value" : ["manager","administrator"]
                }]

    "Attribute": {
        "Id"        : "document-id"
        "DataType"  : "integer"
              "Value"   : 123
    }
    */

    TAILQ_COUNT_SAFE(c, x_attribute, &attr_list, next);

    if (c == 0) {
        return 0;
    } else if (c == 1) {
        evbuffer_add_printf(output, "        \"Attribute\": {\n");
        TAILQ_FOREACH(x_attribute, &attr_list, next) {
            evbuffer_add_printf(output, "            \"Id\": \"%s\"",
                                        x_attribute->id);
            /* Output for the Attribute values */
            if (!(TAILQ_EMPTY(&(x_attribute->values)))) {
                evbuffer_add_printf(output, ",\n");
                normalized_xacml_attribute_values2json_evbuffer(output, x_attribute->values);
                evbuffer_add_printf(output, "\n");
            } else {
                evbuffer_add_printf(output, "\n");
            }
            evbuffer_add_printf(output, "          }");
        }
    } else {
        evbuffer_add_printf(output, "        \"Attribute\": [\n");
        TAILQ_FOREACH(x_attribute, &attr_list, next) {
            first ? first = 0 : evbuffer_add_printf(output, ",\n");

            evbuffer_add_printf(output, "          {\n"
                                        "            \"Id\": \"%s\"",
                                        x_attribute->id);
            /* Output for the Attribute values */
            if (!(TAILQ_EMPTY(&(x_attribute->values)))) {
                evbuffer_add_printf(output, ",\n");
                normalized_xacml_attribute_values2json_evbuffer(output, x_attribute->values);
                evbuffer_add_printf(output, "\n");
            } else {
                evbuffer_add_printf(output, "\n");
            }
            evbuffer_add_printf(output, "          }");
        }
        evbuffer_add_printf(output, "\n        ]");
    }

    return 0;
}

static int
normalized_xacml_categories2json_evbuffer(struct evbuffer *output,
                                          tq_xacml_category_list_t cat_list,
                                          enum ga_xacml_category_e cat_type) {
    struct tq_xacml_category_s *category;
    int    first = 1;
    int c;

    TAILQ_COUNT_SAFE(c, category, &cat_list, next);
    if (c == 0) {
        return 0;
    } else if (c == 1) {
        TAILQ_FOREACH(category, &cat_list, next) {
            if (category->type != cat_type) {
                continue;
            }

            switch (category->type) {
                case GA_XACML_CATEGORY_OBLIGATION:
                    evbuffer_add_printf(output, "      \"Obligation\" : {\n");
                    break;
                case GA_XACML_CATEGORY_ADVICE:
                    evbuffer_add_printf(output, "      \"Advice\" : {\n");
                    break;
                default:
                    evbuffer_add_printf(output, "ERROR: Internal server error\n");
                    return 1;
            }
            if (!(TAILQ_EMPTY(&(category->attributes)))) {
                evbuffer_add_printf(output, "        \"Id\" : \"%s\",\n", category->id);
                normalized_xacml_attributes2json_evbuffer(output, category->attributes);
                evbuffer_add_printf(output, "\n      }");
            } else {
                evbuffer_add_printf(output, "        \"Id\" : \"%s\"\n      }", category->id);
            }
        }
    } else {
        TAILQ_FOREACH(category, &cat_list, next) {
            if (category->type != cat_type) {
                continue;
            }
            if (first) {
                switch (category->type) {
                    case GA_XACML_CATEGORY_OBLIGATION:
                        evbuffer_add_printf(output, "      \"Obligation\" : [\n");
                        break;
                    case GA_XACML_CATEGORY_ADVICE:
                        evbuffer_add_printf(output, "      \"Advice\" : [\n");
                        break;
                    default:
                        evbuffer_add_printf(output, "ERROR: Internal server error\n");
                        return 1;
                }
                first = 0;
            } else {
                evbuffer_add_printf(output, ",\n");
            }

            if (!(TAILQ_EMPTY(&(category->attributes)))) {
                evbuffer_add_printf(output, "{\n        \"Id\" : \"%s\",\n", category->id);
                normalized_xacml_attributes2json_evbuffer(output, category->attributes);
            } else {
                evbuffer_add_printf(output, "{\n        \"Id\" : \"%s\"\n", category->id);
            }

            evbuffer_add_printf(output, "        }\n");
        }
        evbuffer_add_printf(output, "      ]");
    }

    return 0;
}

evhtp_res
pdp_json_output_processor(struct evbuffer *output,
                         struct tq_xacml_response_s *xacml_res) {
    evhtp_res http_res = EVHTP_RES_200;

    /* Response header */
    evbuffer_add_printf(output,
            "{\n"
            "  \"Response\" : {\n"
            "    \"Result\" : {\n"
            "      \"Decision\" : \"%s\"",
            xacml_decision2str(xacml_res->decision));

    /* Obligations */
    if (!(TAILQ_EMPTY(&(xacml_res->obligations)))) {
        evbuffer_add_printf(output, ",\n");
        normalized_xacml_categories2json_evbuffer(output,
                                                  xacml_res->obligations,
                                                  GA_XACML_CATEGORY_OBLIGATION);
    }

    /* Advices */
    if (!(TAILQ_EMPTY(&(xacml_res->advices)))) {
        evbuffer_add_printf(output, ",\n");
        normalized_xacml_categories2json_evbuffer(output,
                                                  xacml_res->obligations,
                                                  GA_XACML_CATEGORY_ADVICE);
    }

    /* IncludeInResult Attributes */
    if (!(TAILQ_EMPTY(&(xacml_res->attributes)))) {
        evbuffer_add_printf(output, ",\n");
        normalized_xacml_attributes2json_evbuffer(output, xacml_res->attributes);
    }

    /* Finalize the Result object */
    evbuffer_add_printf(output,
            "\n"
            "    }\n"
            "  }\n"
            "}\n");

    return http_res;
}



