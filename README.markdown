# __General Authorization__

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

## Current state
Work in progress, but functional and well performing

## Dependencies
* libevhtp (version 1.2.0 or up): https://github.com/ellzey/libevhtp
* libconfuse: http://www.nongnu.org/confuse/
* libxml2: http://www.xmlsoft.org/

### Dependencies of libevhtp:
* libevent2: (with OpenSSL): http://libevent.org/
* OpenSSL: http://www.openssl.org/

## Commandline arguments
* `--conf <configuration file>`

## Known BUGS
* The _syslog_ section's _options_ doesn't work.
* Only the _pdp_ _service_ _type_ can be used. All other listeners with different service types are defunced.
* The _composition_ element in the policy file doesn't work yet.

## Configuration file
* _debug_ accepts "yes" or "no"
* _policyfile_ accepts <relative path to the policy file>. This file will be parsed and loaded as the source for all the rules.
* _syslog_ a section to set Syslog options.
* _listener_ (multiple) a section to configure listeners or listening sockets.
* _bindaddress_ describes the bind address for the listening socket. It supports both IPv4 and IPv6
* _port_ the TCP port number used by the listening socket.
* _backlog_ the configured TCP listener backlog per _listener_
* _threads_ amount of threads that are assigned to handle connections per configured _listener_
* _service_ (multiple) section per _listener_ that describes the URI to trigger on and the service type details.
* _type_ sets the service type and only accepts _pep_, _pdp_ and _pap_.
* _uri_ sets the URI to trigger the functionality of the _service_ _type_


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

## Policy file
* _rules_ sets multiple rules that are to be used as active.
* _composition_ declares that the configured rules are to be a complete match with a request when _anyof_ them match or only when _all_ are matched.
* _rule_ is a **named** section describing a rule to be matched with a request. It states attributes in categories and on a match what kind of result it should return, supporting obligations and advices in that subsection.


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


