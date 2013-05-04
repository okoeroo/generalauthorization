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

## Configuration file example

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
	* _logical_ states how to treat all the categories with attributes. It can be set to __AND__, __OR__ and __NOT__. Set to __AND__ all of the configured categories with all the set attributes must fully be matched to a incoming request. If one attribute or value described in the _rule_ is not found in the request, then rule is not matched. With __OR__ any of the described attributes in its parenting category (optionally with value) needs to match for the rule to be a match. With the __NOT__ it must not match any of the attributes. (the __NOT__ could be changed to __NAND__ or __NOR__).
	* _subject_, _action_, _resource_ and _environment_ are valid categories. Each may be set multiple times, which is equal to placing all the attributes in any of the category sections. A category must have at least one attribute to have any effect.
	* _attribute_ is a section describing one attribute. The attribute is bound to a particular category.
		* _attributeid_ sets the identifier for an attribute. It can be set directly in the category section, but this allows you to only set one attribute per category and is a short-hand notation. It is best to place this tag inside an _attribute_ section.
		* _function_ (optional) sets the evaluation function. Some specific attributes need to me evaluated in a special way. This is described with a _function_. The build-in function __matchvalue__ is means to perform a full string comparison/match of the value in an request with the configured value in a rule.
		* _value_  (optional) sets the value of the _attribute_ described by the _attributeid_. Depending on the _function_ used, the value will be match with those in a request.
	* _result_ is a section which describes what to return in a response message when this rule has matched.
		* _decision_ can be set to __permit__, __deny__, __notapplicable__ and __indeterminate__ and will form the XACML response message' decision when this _rule_ matches.
		* _obligation_ (optional) is a section that describes an XACML obligation to be returned in the Response message on a rule match.
			* _obligationid_ is the identifier of an obligation. The PEP will trigger on this identifier to process the attributes set in this obligation.
			* _attribute_ (optional) section describing an attribute. As it is similar to the _attribute_ in a category section, please see above for details.
				* _attributeid_ sets the identifier for an attribute. As it is similar to the _attributeid_ in a category section, please see above for details.
				* _value_ (optional) (optional) sets the value of the _attribute_ described by the _attributeid_. The returned value will have a datatype of a string.

### Policy file example

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


