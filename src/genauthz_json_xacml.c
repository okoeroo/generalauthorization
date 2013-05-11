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



int
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

int
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

int
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
