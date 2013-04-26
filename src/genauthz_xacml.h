#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>


#ifndef GENAUTHZ_HTTPREST_H
    #define GENAUTHZ_HTTPREST_H

typedef enum {
    GA_XACML_DATATYPE_STRING,
    GA_XACML_DATATYPE_PRIMITIVE,
    GA_XACML_DATATYPE_BOOLEAN,
    GA_XACML_DATATYPE_FLOAT,
    GA_XACML_DATATYPE_DOUBLE,
    GA_XACML_DATATYPE_DECIMAL,
    GA_XACML_DATATYPE_DURATION,
    GA_XACML_DATATYPE_DATETIME,
    GA_XACML_DATATYPE_TIME,
    GA_XACML_DATATYPE_DATE,
    GA_XACML_DATATYPE_GYEARMONTH,
    GA_XACML_DATATYPE_GYEAR,
    GA_XACML_DATATYPE_GMONTHDAY,
    GA_XACML_DATATYPE_GDAY,
    GA_XACML_DATATYPE_GMONTH,
    GA_XACML_DATATYPE_HEXBINARY,
    GA_XACML_DATATYPE_BASE64BINARY,
    GA_XACML_DATATYPE_ANYURI,
    GA_XACML_DATATYPE_QNAME,
    GA_XACML_DATATYPE_NOTATION,
    GA_XACML_DATATYPE_DERIVED,
    GA_XACML_DATATYPE_TOKEN,
    GA_XACML_DATATYPE_LANGUAGE,
    GA_XACML_DATATYPE_IDREFS,
    GA_XACML_DATATYPE_ENTITIES,
    GA_XACML_DATATYPE_NMTOKEN,
    GA_XACML_DATATYPE_NMTOKENS,
    GA_XACML_DATATYPE_NAME,
    GA_XACML_DATATYPE_NCNAME,
    GA_XACML_DATATYPE_ID,
    GA_XACML_DATATYPE_IDREF,
    GA_XACML_DATATYPE_ENTITY,
    GA_XACML_DATATYPE_INTEGER,
    GA_XACML_DATATYPE_NONPOSITIVEINTEGER,
    GA_XACML_DATATYPE_NEGATIVEINTEGER,
    GA_XACML_DATATYPE_LONG,
    GA_XACML_DATATYPE_INT,
    GA_XACML_DATATYPE_SHORT,
    GA_XACML_DATATYPE_BYTE,
    GA_XACML_DATATYPE_NONNEGATIVEINTEGER,
    GA_XACML_DATATYPE_UNSIGNEDLONG,
    GA_XACML_DATATYPE_UNSIGNEDINT,
    GA_XACML_DATATYPE_UNSIGNEDSHORT,
    GA_XACML_DATATYPE_UNSIGNEDBYTE,
    GA_XACML_DATATYPE_POSITIVEINTEGER,
    GA_XACML_DATATYPE_UNKNOWN
} ga_xacml_datatype_t;

enum ga_xacml_decision_e {
    GA_XACML_DECISION_PERMIT,
    GA_XACML_DECISION_DENY,
    GA_XACML_DECISION_INDETERMINATE,
    GA_XACML_DECISION_NOTAPPLICABLE
};

enum ga_xacml_category_e {
    GA_XACML_CATEGORY_SUBJECT,
    GA_XACML_CATEGORY_ACTION,
    GA_XACML_CATEGORY_RESOURCE,
    GA_XACML_CATEGORY_ENVIRONMENT,
    GA_XACML_CATEGORY_OBLIGATION,
    GA_XACML_CATEGORY_UNKNOWN
};

enum ga_xacml_boolean_e {
    GA_XACML_NO = 0,
    GA_XACML_YES = 1
};

struct tq_xacml_attribute_value_s {
    char *datatype_id;
    ga_xacml_datatype_t datatype;
    void *data;
    TAILQ_ENTRY(tq_xacml_attribute_s) next;
};

struct tq_xacml_attribute_s {
    char *id;
    enum ga_xacml_boolean_e include_in_result;
    TAILQ_HEAD(, tq_xacml_attribute_value_s) values;
    TAILQ_ENTRY(tq_xacml_attribute_s) next;
};

struct tq_xacml_category_s {
    enum ga_xacml_category_e type;
    unsigned char *id;
    TAILQ_HEAD(, tq_xacml_attribute_s) attributes;
    TAILQ_ENTRY(tq_xacml_category_s) next;
};

struct tq_xacml_response_s {
    unsigned char *ns;
    enum ga_xacml_decision_e decision;
    TAILQ_HEAD(, tq_xacml_category_s) obligations;
    TAILQ_HEAD(, tq_xacml_category_s) advices;
    TAILQ_HEAD(, tq_xacml_attribute_s) attributes;
};

struct tq_xacml_request_s {
    unsigned char *ns;
    TAILQ_HEAD(, tq_xacml_category_s) categories;
};


#endif /* GENAUTHZ_HTTPREST_H */
