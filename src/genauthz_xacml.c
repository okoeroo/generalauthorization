#include <stdio.h>
#include <stdlib.h>

#include "genauthz_xacml.h"


static int xdatatype_tree_initialized = 0;

struct datatype {
    ga_xacml_datatype_t type;
    const char *str;

    RB_ENTRY(datatype) entry;
};

static int
datatype_cmp(void * _a, void * _b) {
    struct datatype * a = _a;
    struct datatype * b = _b;

    return b->type - a->type;
}


RB_HEAD(datatype_tree, datatype) datatype_head = RB_INITIALIZER(&datatype_head);
RB_GENERATE(datatype_tree, datatype, entry, datatype_cmp)

#define xdatatype_add(xdatatype, cstr) do {                    \
        struct datatype * c = malloc(sizeof(struct datatype)); \
                                                               \
        c->type = xdatatype;                                   \
        c->str  = cstr;                                        \
                                                               \
        RB_INSERT(datatype_tree, &datatype_head, c);           \
} while (0)



void
datatype_list_init(void) {
    if (xdatatype_tree_initialized) {
        /* Already initialized. */
        return;
    }
        struct datatype * c = malloc(sizeof(struct datatype));

    /* Initializations */
    xdatatype_add(GA_XACML_DATATYPE_STRING, "http://www.w3.org/2001/XMLSchema#string");
    xdatatype_add(GA_XACML_DATATYPE_LONG, "http://www.w3.org/2001/XMLSchema#");
    xdatatype_add(GA_XACML_DATATYPE_INT, "http://www.w3.org/2001/XMLSchema#");
    xdatatype_add(GA_XACML_DATATYPE_SHORT, "http://www.w3.org/2001/XMLSchema#");
    xdatatype_add(GA_XACML_DATATYPE_INTEGER, "http://www.w3.org/2001/XMLSchema#integer");
    xdatatype_add(GA_XACML_DATATYPE_PRIMITIVE, "http://www.w3.org/2001/XMLSchema#primitive");
    xdatatype_add(GA_XACML_DATATYPE_BOOLEAN, "http://www.w3.org/2001/XMLSchema#boolean");
    xdatatype_add(GA_XACML_DATATYPE_FLOAT, "http://www.w3.org/2001/XMLSchema#float");
    xdatatype_add(GA_XACML_DATATYPE_DOUBLE, "http://www.w3.org/2001/XMLSchema#double");
    xdatatype_add(GA_XACML_DATATYPE_DECIMAL, "http://www.w3.org/2001/XMLSchema#decimal");
    xdatatype_add(GA_XACML_DATATYPE_DURATION, "http://www.w3.org/2001/XMLSchema#duration");
    xdatatype_add(GA_XACML_DATATYPE_DATETIME, "http://www.w3.org/2001/XMLSchema#datetime");
    xdatatype_add(GA_XACML_DATATYPE_TIME, "http://www.w3.org/2001/XMLSchema#time");
    xdatatype_add(GA_XACML_DATATYPE_DATE, "http://www.w3.org/2001/XMLSchema#date");
    xdatatype_add(GA_XACML_DATATYPE_GYEARMONTH, "http://www.w3.org/2001/XMLSchema#gyearmonth");
    xdatatype_add(GA_XACML_DATATYPE_GYEAR, "http://www.w3.org/2001/XMLSchema#gyear");
    xdatatype_add(GA_XACML_DATATYPE_GMONTHDAY, "http://www.w3.org/2001/XMLSchema#gmonthday");
    xdatatype_add(GA_XACML_DATATYPE_GDAY, "http://www.w3.org/2001/XMLSchema#gday");
    xdatatype_add(GA_XACML_DATATYPE_GMONTH, "http://www.w3.org/2001/XMLSchema#gmonth");
    xdatatype_add(GA_XACML_DATATYPE_HEXBINARY, "http://www.w3.org/2001/XMLSchema#hexbinary");
    xdatatype_add(GA_XACML_DATATYPE_BASE64BINARY, "http://www.w3.org/2001/XMLSchema#base64binary");
    xdatatype_add(GA_XACML_DATATYPE_ANYURI, "http://www.w3.org/2001/XMLSchema#anyuri");
    xdatatype_add(GA_XACML_DATATYPE_QNAME, "http://www.w3.org/2001/XMLSchema#qname");
    xdatatype_add(GA_XACML_DATATYPE_NOTATION, "http://www.w3.org/2001/XMLSchema#notation");
    xdatatype_add(GA_XACML_DATATYPE_DERIVED, "http://www.w3.org/2001/XMLSchema#derived");
    xdatatype_add(GA_XACML_DATATYPE_TOKEN, "http://www.w3.org/2001/XMLSchema#token");
    xdatatype_add(GA_XACML_DATATYPE_LANGUAGE, "http://www.w3.org/2001/XMLSchema#language");
    xdatatype_add(GA_XACML_DATATYPE_IDREFS, "http://www.w3.org/2001/XMLSchema#idrefs");
    xdatatype_add(GA_XACML_DATATYPE_ENTITIES, "http://www.w3.org/2001/XMLSchema#entities");
    xdatatype_add(GA_XACML_DATATYPE_NMTOKEN, "http://www.w3.org/2001/XMLSchema#nmtoken");
    xdatatype_add(GA_XACML_DATATYPE_NMTOKENS, "http://www.w3.org/2001/XMLSchema#nmtokens");
    xdatatype_add(GA_XACML_DATATYPE_NAME, "http://www.w3.org/2001/XMLSchema#name");
    xdatatype_add(GA_XACML_DATATYPE_NCNAME, "http://www.w3.org/2001/XMLSchema#ncname");
    xdatatype_add(GA_XACML_DATATYPE_ID, "http://www.w3.org/2001/XMLSchema#id");
    xdatatype_add(GA_XACML_DATATYPE_IDREF, "http://www.w3.org/2001/XMLSchema#idref");
    xdatatype_add(GA_XACML_DATATYPE_ENTITY, "http://www.w3.org/2001/XMLSchema#entity");
    xdatatype_add(GA_XACML_DATATYPE_NONPOSITIVEINTEGER, "http://www.w3.org/2001/XMLSchema#nonpositiveinteger");
    xdatatype_add(GA_XACML_DATATYPE_NEGATIVEINTEGER, "http://www.w3.org/2001/XMLSchema#negativeinteger");
    xdatatype_add(GA_XACML_DATATYPE_BYTE, "http://www.w3.org/2001/XMLSchema#byte");
    xdatatype_add(GA_XACML_DATATYPE_NONNEGATIVEINTEGER, "http://www.w3.org/2001/XMLSchema#nonnegativeinteger");
    xdatatype_add(GA_XACML_DATATYPE_UNSIGNEDLONG, "http://www.w3.org/2001/XMLSchema#unsignedlong");
    xdatatype_add(GA_XACML_DATATYPE_UNSIGNEDINT, "http://www.w3.org/2001/XMLSchema#unsignedint");
    xdatatype_add(GA_XACML_DATATYPE_UNSIGNEDSHORT, "http://www.w3.org/2001/XMLSchema#unsignedshort");
    xdatatype_add(GA_XACML_DATATYPE_UNSIGNEDBYTE, "http://www.w3.org/2001/XMLSchema#unsignedbyte");
    xdatatype_add(GA_XACML_DATATYPE_POSITIVEINTEGER, "http://www.w3.org/2001/XMLSchema#positiveinteger");
    xdatatype_add(GA_XACML_DATATYPE_UNKNOWN, "unknown");

    xdatatype_tree_initialized = 1;
}

const char *
datatype_to_str(ga_xacml_datatype_t type) {
    struct datatype   c;
    struct datatype * found;

    c.type = type;

    if (!(found = RB_FIND(datatype_tree, &datatype_head, &c))) {
        return "unknown";
    }

    return found->str;
}


