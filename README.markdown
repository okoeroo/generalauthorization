# _General Authorization_

### _Faster than light XACML 3.0 REST service_
*****

## Author
Oscar Koeroo <okoeroo@gmail.com>

## What is it?
This is an XACML 3.0 REST PDP service. Currently only supporting XML based
XACML, but future work would include the support for JSON based requests and
responses.

## ...but why?
I had an itch to scratch and the saml2-xacml2 PDP based on gSOAP didn't perform
to my satisfaction and wanted experience the do's and don'ts of creating a well
performing service.

## State
Work in progress, but functional and well performing

## Dependencies
* libevhtp (version 1.2.0 or up): https://github.com/ellzey/libevhtp
* libconfuse: http://www.nongnu.org/confuse/
* libxml2: http://www.xmlsoft.org/

### Dependencies of libevhtp:
* libevent2: (with OpenSSL): http://libevent.org/
* OpenSSL: http://www.openssl.org/

## Commandline arguments
* --conf <configuration file>

## Configuration file

`
debug = no
policyfile = tests/policy.conf

syslog {
    ident = generalauthz
    facility = daemon
    options += PID
    options += NDELAY
    options += PERROR
}
listener {
    bindaddress = ipv4:127.0.0.1
    port = 8080
    threads = 2

    service {
        type = pep
        uri = authorization/pep/
    }
    service {
        type = pap
        uri = authorization/pap/
    }
}
listener {
    bindaddress = ipv4:0.0.0.0
    port = 8081
    backlog = 2000
    threads = 3

    service {
        type = pdp
        uri = authorization/pdp/
    }
    service {
        type = pep
        uri = authorization/pep/
    }
}
`

## Policy file
`
rules = {foo, bar}
composition = anyof


rule foo {
    logical = AND
    subject {
        attribute {
            attributeid = urn:org:apache:tomcat:user-attr:clearance
            function = matchvalue 
            value = SECRET
        }
        attributeid = urn:org:apache:tomcat
        function = matchvalue 
        value = FOO
    }
    result {
        decision = indeterminate
    }
}

rule bar {
    # composition = anyof
    # rule = bar
    logical = OR
    subject {
        attributeid = urn:org:apache:tomcat:user-attr:clearance
        function = matchvalue 
        value = SECRET
    }
    action {
        attributeid = urn:oasis:names:tc:xacml:1.0:action:action-id
        function = matchvalue
        value = view
    }
    result {
        decision = permit
        obligation {
            obligationid = urn:omg:wtf:bbq:obligation:id
            attribute {
                attributeid = urn:oasis:names:tc:xacml:1.0:action:action-id
                value = view
            }
        }
    }
}
`
