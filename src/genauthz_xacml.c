#include "ga_config.h"
#include "genauthz/genauthz_xacml.h"

RB_HEAD(ga_xml_datatype_tree, ga_xml_datatype);

int ga_xml_datatype_tree_initialized = 0;
struct ga_xml_datatype_tree ga_xml_datatype_head;


struct ga_xml_datatype {
    RB_ENTRY(ga_xml_datatype) entry;

    ga_xacml_datatype_t type;
    const char *str;
};

static int ga_xml_datatype_cmp(struct ga_xml_datatype *, struct ga_xml_datatype *);

/* RB_HEAD(datatype_tree, datatype) datatype_head = RB_INITIALIZER(&datatype_head); */

RB_PROTOTYPE(ga_xml_datatype_tree, ga_xml_datatype, entry, ga_xml_datatype_cmp)
RB_GENERATE(ga_xml_datatype_tree, ga_xml_datatype, entry, ga_xml_datatype_cmp)

#define xml_datatype_add(xdatatype, cstr) do {                        \
        struct ga_xml_datatype *c;                                    \
        c = malloc(sizeof(struct ga_xml_datatype));                   \
        c->type = xdatatype;                                          \
        c->str  = cstr;                                               \
                                                                      \
        RB_INSERT(ga_xml_datatype_tree, &ga_xml_datatype_head, c);    \
} while (0)

static int
ga_xml_datatype_cmp(struct ga_xml_datatype *a, struct ga_xml_datatype *b) {
    return b->type - a->type;
}

void
datatype_list_init(void) {
    if (ga_xml_datatype_tree_initialized) {
        /* Already initialized. */
        return;
    }

    RB_INIT(&ga_xml_datatype_head);

    /* Initializations */
    xml_datatype_add(GA_XACML_DATATYPE_STRING, "http://www.w3.org/2001/XMLSchema#string");
    xml_datatype_add(GA_XACML_DATATYPE_LONG, "http://www.w3.org/2001/XMLSchema#");
    xml_datatype_add(GA_XACML_DATATYPE_INT, "http://www.w3.org/2001/XMLSchema#");
    xml_datatype_add(GA_XACML_DATATYPE_SHORT, "http://www.w3.org/2001/XMLSchema#");
    xml_datatype_add(GA_XACML_DATATYPE_INTEGER, "http://www.w3.org/2001/XMLSchema#integer");
    xml_datatype_add(GA_XACML_DATATYPE_PRIMITIVE, "http://www.w3.org/2001/XMLSchema#primitive");
    xml_datatype_add(GA_XACML_DATATYPE_BOOLEAN, "http://www.w3.org/2001/XMLSchema#boolean");
    xml_datatype_add(GA_XACML_DATATYPE_FLOAT, "http://www.w3.org/2001/XMLSchema#float");
    xml_datatype_add(GA_XACML_DATATYPE_DOUBLE, "http://www.w3.org/2001/XMLSchema#double");
    xml_datatype_add(GA_XACML_DATATYPE_DECIMAL, "http://www.w3.org/2001/XMLSchema#decimal");
    xml_datatype_add(GA_XACML_DATATYPE_DURATION, "http://www.w3.org/2001/XMLSchema#duration");
    xml_datatype_add(GA_XACML_DATATYPE_DATETIME, "http://www.w3.org/2001/XMLSchema#datetime");
    xml_datatype_add(GA_XACML_DATATYPE_TIME, "http://www.w3.org/2001/XMLSchema#time");
    xml_datatype_add(GA_XACML_DATATYPE_DATE, "http://www.w3.org/2001/XMLSchema#date");
    xml_datatype_add(GA_XACML_DATATYPE_GYEARMONTH, "http://www.w3.org/2001/XMLSchema#gyearmonth");
    xml_datatype_add(GA_XACML_DATATYPE_GYEAR, "http://www.w3.org/2001/XMLSchema#gyear");
    xml_datatype_add(GA_XACML_DATATYPE_GMONTHDAY, "http://www.w3.org/2001/XMLSchema#gmonthday");
    xml_datatype_add(GA_XACML_DATATYPE_GDAY, "http://www.w3.org/2001/XMLSchema#gday");
    xml_datatype_add(GA_XACML_DATATYPE_GMONTH, "http://www.w3.org/2001/XMLSchema#gmonth");
    xml_datatype_add(GA_XACML_DATATYPE_HEXBINARY, "http://www.w3.org/2001/XMLSchema#hexbinary");
    xml_datatype_add(GA_XACML_DATATYPE_BASE64BINARY, "http://www.w3.org/2001/XMLSchema#base64binary");
    xml_datatype_add(GA_XACML_DATATYPE_ANYURI, "http://www.w3.org/2001/XMLSchema#anyuri");
    xml_datatype_add(GA_XACML_DATATYPE_QNAME, "http://www.w3.org/2001/XMLSchema#qname");
    xml_datatype_add(GA_XACML_DATATYPE_NOTATION, "http://www.w3.org/2001/XMLSchema#notation");
    xml_datatype_add(GA_XACML_DATATYPE_DERIVED, "http://www.w3.org/2001/XMLSchema#derived");
    xml_datatype_add(GA_XACML_DATATYPE_TOKEN, "http://www.w3.org/2001/XMLSchema#token");
    xml_datatype_add(GA_XACML_DATATYPE_LANGUAGE, "http://www.w3.org/2001/XMLSchema#language");
    xml_datatype_add(GA_XACML_DATATYPE_IDREFS, "http://www.w3.org/2001/XMLSchema#idrefs");
    xml_datatype_add(GA_XACML_DATATYPE_ENTITIES, "http://www.w3.org/2001/XMLSchema#entities");
    xml_datatype_add(GA_XACML_DATATYPE_NMTOKEN, "http://www.w3.org/2001/XMLSchema#nmtoken");
    xml_datatype_add(GA_XACML_DATATYPE_NMTOKENS, "http://www.w3.org/2001/XMLSchema#nmtokens");
    xml_datatype_add(GA_XACML_DATATYPE_NAME, "http://www.w3.org/2001/XMLSchema#name");
    xml_datatype_add(GA_XACML_DATATYPE_NCNAME, "http://www.w3.org/2001/XMLSchema#ncname");
    xml_datatype_add(GA_XACML_DATATYPE_ID, "http://www.w3.org/2001/XMLSchema#id");
    xml_datatype_add(GA_XACML_DATATYPE_IDREF, "http://www.w3.org/2001/XMLSchema#idref");
    xml_datatype_add(GA_XACML_DATATYPE_ENTITY, "http://www.w3.org/2001/XMLSchema#entity");
    xml_datatype_add(GA_XACML_DATATYPE_NONPOSITIVEINTEGER, "http://www.w3.org/2001/XMLSchema#nonpositiveinteger");
    xml_datatype_add(GA_XACML_DATATYPE_NEGATIVEINTEGER, "http://www.w3.org/2001/XMLSchema#negativeinteger");
    xml_datatype_add(GA_XACML_DATATYPE_BYTE, "http://www.w3.org/2001/XMLSchema#byte");
    xml_datatype_add(GA_XACML_DATATYPE_NONNEGATIVEINTEGER, "http://www.w3.org/2001/XMLSchema#nonnegativeinteger");
    xml_datatype_add(GA_XACML_DATATYPE_UNSIGNEDLONG, "http://www.w3.org/2001/XMLSchema#unsignedlong");
    xml_datatype_add(GA_XACML_DATATYPE_UNSIGNEDINT, "http://www.w3.org/2001/XMLSchema#unsignedint");
    xml_datatype_add(GA_XACML_DATATYPE_UNSIGNEDSHORT, "http://www.w3.org/2001/XMLSchema#unsignedshort");
    xml_datatype_add(GA_XACML_DATATYPE_UNSIGNEDBYTE, "http://www.w3.org/2001/XMLSchema#unsignedbyte");
    xml_datatype_add(GA_XACML_DATATYPE_POSITIVEINTEGER, "http://www.w3.org/2001/XMLSchema#positiveinteger");
    xml_datatype_add(GA_XACML_DATATYPE_UNKNOWN, "unknown");

    ga_xml_datatype_tree_initialized = 1;
}

const char *
datatype_to_str(ga_xacml_datatype_t type) {
    struct ga_xml_datatype  c;
    struct ga_xml_datatype *found;

    c.type = type;

    if (!(found = RB_FIND(ga_xml_datatype_tree, &ga_xml_datatype_head, &c))) {
        return "unknown";
    }

    return found->str;
}


