#include <stdint.h>
#include "queue.h"
#include "tree.h"


#ifndef GENAUTHZ_XACML_H
    #define GENAUTHZ_XACML_H

enum ga_rule_composition_e {
    GA_RULE_COMPOSITION_ANYOF,
    GA_RULE_COMPOSITION_ALL,
    GA_RULE_COMPOSITION_ONE
};

typedef enum {
    GA_XACML_DATATYPE_STRING,
    GA_XACML_DATATYPE_INTEGER,
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

/* function */
void datatype_list_init(void);
const char *datatype_to_str(ga_xacml_datatype_t type);


enum ga_xacml_decision_e {
    GA_XACML_DECISION_PERMIT,
    GA_XACML_DECISION_DENY,
    GA_XACML_DECISION_INDETERMINATE,
    GA_XACML_DECISION_NOTAPPLICABLE
};

enum ga_xacml_category_e {
    GA_XACML_CATEGORY_UNDEFINED,
    GA_XACML_CATEGORY_UNKNOWN,
    GA_XACML_CATEGORY_SUBJECT,
    GA_XACML_CATEGORY_ACTION,
    GA_XACML_CATEGORY_RESOURCE,
    GA_XACML_CATEGORY_ENVIRONMENT,
    GA_XACML_CATEGORY_OBLIGATION,
    GA_XACML_CATEGORY_ADVICE
};

enum ga_xacml_boolean_e {
    GA_XACML_NO = 0,
    GA_XACML_YES = 1
};

struct tq_xacml_attribute_value_s {
    unsigned char *datatype_id;
    ga_xacml_datatype_t datatype;
    void *data;
    TAILQ_ENTRY(tq_xacml_attribute_value_s) next;
};
typedef struct tq_xacml_attribute_value_list_s tq_xacml_attribute_value_list_t;
TAILQ_HEAD(tq_xacml_attribute_value_list_s, tq_xacml_attribute_value_s);

struct tq_xacml_attribute_s {
    unsigned char *id;
    enum ga_xacml_boolean_e include_in_result;
    tq_xacml_attribute_value_list_t values;
    TAILQ_ENTRY(tq_xacml_attribute_s) next;
};
typedef struct tq_xacml_attribute_list_s tq_xacml_attribute_list_t;
TAILQ_HEAD(tq_xacml_attribute_list_s, tq_xacml_attribute_s);

struct tq_xacml_category_s {
    enum ga_xacml_category_e type;
    unsigned char *id;
    tq_xacml_attribute_list_t attributes;
    TAILQ_ENTRY(tq_xacml_category_s) next;
};
typedef struct tq_xacml_category_list_s tq_xacml_category_list_t;
TAILQ_HEAD(tq_xacml_category_list_s, tq_xacml_category_s);

struct tq_xacml_response_s {
    unsigned char *ns;
    enum ga_xacml_decision_e decision;
    tq_xacml_category_list_t obligations;
    tq_xacml_category_list_t advices;
    tq_xacml_attribute_list_t attributes;
};

struct tq_xacml_request_s {
    unsigned char *ns;
    tq_xacml_category_list_t categories;
};


struct tq_xacml_decision_s {
    enum ga_xacml_decision_e decision;
    tq_xacml_category_list_t obligations;
    tq_xacml_category_list_t advices;
};

enum ga_xacml_logical_e {
    GA_XACML_LOGICAL_AND,
    GA_XACML_LOGICAL_OR,
    GA_XACML_LOGICAL_NOR,
    GA_XACML_LOGICAL_NAND,
    GA_XACML_LOGICAL_NOT
};

struct tq_xacml_rule_s {
    char *name;
    enum ga_xacml_logical_e logical;
    tq_xacml_category_list_t categories;

    struct tq_xacml_decision_s *decision;
    uint64_t rule_call_count;

    TAILQ_HEAD(, tq_xacml_rule_s) inherited_rules;
    TAILQ_ENTRY(tq_xacml_rule_s) next;
};
typedef struct tq_xacml_rule_list_s tq_xacml_rule_list_t;
TAILQ_HEAD(tq_xacml_rule_list_s, tq_xacml_rule_s);

struct xacml_policy_s {
    enum ga_rule_composition_e composition;
    tq_xacml_rule_list_t xacml_rule_list;
};

#endif /* GENAUTHZ_HTTPREST_H */
