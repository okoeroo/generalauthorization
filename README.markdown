# __General Authorization__

### _Faster than light XACML 3.0 REST service_
*****

## Author
Oscar Koeroo <okoeroo@gmail.com>

## What is it?
This is an XACML 3.0 REST PDP service which supports both the XML based XACML
and features the JSON profile request and response messages too.  It will also
support external call-outs through a plug-in framework triggered by the policy
rules.

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
* libjansson: http://www.digip.org/jansson/

### Dependencies of libevhtp:
* libevent2: (with OpenSSL): http://libevent.org/
* OpenSSL: http://www.openssl.org/
* pthreads: http://en.wikipedia.org/wiki/POSIX_Threads

## Commandline arguments
* `--conf <configuration file>`

## Known BUGS
* The _syslog_ section's _options_ doesn't work.
* The _composition_ element in the policy file doesn't work yet.
* The _plugin_uninit_ element in the policy file doesn't work yet.

## Go with the Flow
There are two distinct phases
1. Start up time
  1. Load configuration file
  2. Setup Syslog details
  3. Bind the sockets, when running as root, downgrade to __nobody:nogroup__
  4. Load the XACML policy file
  5. For each of the call-outs, load the shared object file and run the _func_name_init_
2. PDP
  1. Wait for XACML 3 REST profile request in XML and JSON
  2. Receiving data (post-SSL) in event buffers and reroute it to the threadpool (libevhtp/openssl/libevent2)
  3. Call the HTTP request handler (libevhtp)
  4. Build a request_mngr_t struct (GenAuthZ)
  5. Check the HTTP method and the Accept + Content-Type data and select the XML or JSON parser
  6. Normalize the XACML input to GenAuthZ objects
  7. XACML policy evaluation based on the policy configuration file.
  8. On rule hit; execute the _rule_hit_cb_ callbacks which are defined (if any) per rule.
  9. Transform the normalized XACML to JSON or XML, based on the Accept header of the request.
  10. Transfer the HTTP response (libevhtp/openssl/libevent2)
3. PAP
  1. Wait for a GET on the listening socket and URI combination
  2. Push the loaded policy as human-readable output
4. CONTROL
  1. Wait for a GET on the listening socket and URI combination
  2. Push activity stats and detailed information about the listener socket binds, thread configuration and usage stats.

## Configuration file
* _debug_ accepts __yes__ or __no__
* _policyfile_ accepts a __relative path__ to the policy file. This file will be parsed and loaded as the source for all the rules.
* _syslog_ a section to set Syslog options.
* _listener_ (multiple) a section to configure listeners or listening sockets.
* _bindaddress_ describes the bind address for the listening socket. It supports both IPv4 and IPv6
* _port_ the TCP port number used by the listening socket.
* _backlog_ the configured TCP listener backlog per _listener_
* _threads_ amount of threads that are assigned to handle connections per configured _listener_
* _service_ (multiple) section per _listener_ that describes the URI to trigger on and the service type details.
* _type_ sets the service type and only accepts __pep__, __pdp__ and __pap__.
* _uri_ sets the URI to trigger the functionality of the _service_ _type_

### Functional service types
* _pap_ in GET mode only
* _control_ in GET mode only
* _pdp_ only accepts POST on the specific _pdp_ URI. The redirect feature from the profile is not implemented.

### Configuration file example

	debug = no
	policyfile = tests/policy.conf

	syslog {
		ident = generalauthz
		facility = daemon
		options = PID
		options += NDELAY
		options += PERROR
	}
	listener {
		bindaddress = ipv4:127.0.0.1
		port = 8080

		service {
			type = control
			uri = control/
			threads = 2
		}
		service {
			type = pap
			uri = authorization/pap/
			threads = 2
		}
		service {
			type = pep
			uri = authorization/pep/
			threads = 1
		}
	}
	listener {
		bindaddress = ipv4:0.0.0.0
		port = 8081
		backlog = 2000

		service {
			type = pdp
			uri = authorization/pdp/
			threads = 8
		}
	}

## Example PAP GET output

	$ curl -v localhost:8080/authorization/pap/
	* About to connect() to localhost port 8080 (#0)
	*   Trying 127.0.0.1...
	* Adding handle: conn: 0x19b0800
	* Adding handle: send: 0
	* Adding handle: recv: 0
	* Curl_addHandleToPipeline: length: 1
	* - Conn 0 (0x19b0800) send_pipe: 1, recv_pipe: 0
	* Connected to localhost (127.0.0.1) port 8080 (#0)
	> GET /authorization/pap/ HTTP/1.1
	> User-Agent: curl/7.28.1-DEV
	> Host: localhost:8080
	> Accept: */*
	>
	< HTTP/1.1 200 OK
	< Content-Length: 649
	< Content-Type: text/plain
	<
	= XACML Policy =
	Composition: ANYOF
	  Rule name: foo
		logical: AND
		Subject
		  AttributeId: urn:org:apache:tomcat
			Datatype: STRING
			Data: "FOO"
		Decision: Intermediate
	  Rule name: bar
		logical: OR
		Subject
		  AttributeId: urn:org:apache:tomcat:user-attr:clearance
			Datatype: STRING
			Data: "SECRET"
		Action
		  AttributeId: urn:oasis:names:tc:xacml:1.0:action:action-id
			Datatype: STRING
			Data: "view"
		Decision: Permit
		Obligation: urn:omg:wtf:bbq:obligation:id
		  AttributeId: urn:oasis:names:tc:xacml:1.0:action:action-id
			Datatype: STRING
			Data: "view"
	* Connection #0 to host localhost left intact

## Example CONTROL GET output

	$ curl -v localhost:8080/control/
	* About to connect() to localhost port 8080 (#0)
	*   Trying 127.0.0.1...
	* Adding handle: conn: 0x9567b0
	* Adding handle: send: 0
	* Adding handle: recv: 0
	* Curl_addHandleToPipeline: length: 1
	* - Conn 0 (0x9567b0) send_pipe: 1, recv_pipe: 0
	* Connected to localhost (127.0.0.1) port 8080 (#0)
	> GET /control/ HTTP/1.1
	> User-Agent: curl/7.28.1-DEV
	> Host: localhost:8080
	> Accept: */*
	>
	< HTTP/1.1 200 OK
	< Content-Length: 804
	< Content-Type: text/plain
	<
	= General Authorization 0.0.3 =
	  1 Bound to IP        :   ipv4:127.0.0.1
		Port               :   8080
		Backlog            :   1024
		Listener hit count :   1
		  0 URI            :   /control/
			Thread count   :   1
			URI hit count  :   0
		  0 URI            :   /authorization/pap/
			Thread count   :   1
			URI hit count  :   1
	  2 Bound to IP        :   ipv4:0.0.0.0
		Port               :   8081
		Backlog            :   2000
		Listener hit count :   0
		  0 URI            :   /authorization/pdp/
			Thread count   :   1
			URI hit count  :   0
		  0 URI            :   /authorization/pep/
			Thread count   :   1
			URI hit count  :   0
		  0 URI            :   /control
			Thread count   :   1
			URI hit count  :   0
	* Connection #0 to host localhost left intact

## Policy file
* _rules_ sets multiple rules that are to be used as active.
* _composition_ declares that the configured rules are to be a complete match with a request when _anyof_ them match, only when _all_ or __one__ are matched.
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
	* _callout_ is a section which describes which callout is to be fired when this rule is matched. The callout is a shared object which will be opened with dlopen(). The function names will each be dlsym()-ed.
		* _plugin_ The path to the shared object file that has at least an __genauthz_rule_hit_cb__, optionally but adviced __genauthz_plugin_init_cb__ and optionally __genauthz_plugin_uninit_cb__.
		* _func_name_init_ this function will be used to initialize the plugin. It will get an int argc and char **argv to initialize. The array of argv elements are set in the __init_argv__ option.
		* _func_name_uninit_ this function will be used to uninitialize the plugin. No parameters are given for this function. Using this function is optional.
		* _rule_hit_cb_ set the function name that will be called with an request_mngr_t * which contains everything about the request (e.g. evhtp request and network context, normalized XACML request and response and all the policies). It also contains a tq_xacml_rule_t * which points to the rule that was hit/triggered.

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
		callout {
			plugin = /the/path/to/your/libyourspecialcallout.so
			func_name_init = funcname_init
			init_argv = {"-v", "--plugconf", "/etc/special.conf"}
			func_name_uninit = funcname_uninit
			func_name_rule_hit = funcname_rule_hit_cb
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


## Request message
You can only POST to the URI specified as the __pdp__ typed _URI_. See above for configuration.
_Content-Type_ header: What the client or _PEP_ is using in its Request or POST message. The following values are usable, all other will fail:
* application/xacml+json
* application/xacml+xml
_Accept_ header: What the client or _PEP_ accepts as returned Response. The following values are usable, all other will fail:
* application/xacml+json
* application/xacml+xml
The _Content-Type_ header value and _Accept_ header SHOULD be set the same. This is adviced, but you MAY mix them to get a JSON Response based on an XML Request or vice-versa.

### Example Request XML

	<xacml-ctx:request returnpolicyidlist="true" combineddecision="false" xmlns:xacml-ctx="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17">
		<xacml-ctx:attributes category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment">
		</xacml-ctx:attributes>
		<xacml-ctx:attributes category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
			<xacml-ctx:attribute attributeid="urn:org:apache:tomcat:user-attr:clearance" includeinresult="true">
				<xacml-ctx:attributevalue datatype="http://www.w3.org/2001/XMLSchema#string">SECRET</xacml-ctx:attributevalue>
			</xacml-ctx:attribute>
			<xacml-ctx:attribute attributeid="company" includeinresult="true">
				<xacml-ctx:attributevalue datatype="http://www.w3.org/2001/XMLSchema#string">Axiomatics</xacml-ctx:attributevalue>
			</xacml-ctx:attribute>
			<xacml-ctx:attribute attributeid="urn:org:apache:tomcat:user-role" includeinresult="true">
				<xacml-ctx:attributevalue datatype="http://www.w3.org/2001/XMLSchema#string">manager</xacml-ctx:attributevalue>
			</xacml-ctx:attribute>
		</xacml-ctx:attributes>
		<xacml-ctx:attributes category="urn:oasis:names:tc:xacml:3.0:attribute-category:action">
			<xacml-ctx:attribute attributeid="urn:oasis:names:tc:xacml:1.0:action:action-id" includeinresult="true">
				<xacml-ctx:attributevalue datatype="http://www.w3.org/2001/XMLSchema#string">view</xacml-ctx:attributevalue>
			</xacml-ctx:attribute>
		</xacml-ctx:attributes>
		<xacml-ctx:attributes category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource">
			<xacml-ctx:attribute attributeid="classification" includeinresult="true">
				<xacml-ctx:attributevalue datatype="http://www.w3.org/2001/XMLSchema#string">CONFIDENTIAL</xacml-ctx:attributevalue>
			</xacml-ctx:attribute>
			<xacml-ctx:attribute attributeid="urn:oasis:names:tc:xacml:1.0:resource:resource-id" includeinresult="true">
				<xacml-ctx:attributevalue datatype="http://www.w3.org/2001/XMLSchema#string">document</xacml-ctx:attributevalue>
			</xacml-ctx:attribute>
		</xacml-ctx:attributes>
	</xacml-ctx:request>


### Example Request JSON

	{
		"Request" : {
			"Subject" : {
				"Attributes": [
					{
						"Id" : "urn:org:apache:tomcat:user-attr:clearance",
						"IncludeInResult" : true,
						"Value" : "SECRET"
					},
					{
						"Id" : "company",
						"IncludeInResult" : true,
						"Value" : "Axiomatics"
					},
					{
						"Id" : "urn:org:apache:tomcat:user-role",
						"IncludeInResult" : true,
						"Value" : "manager"
					},
					{
						"Id" : "test_diff_datatype",
						"IncludeInResult" : true,
						"Value" : "manager",
						"DataType" : "anyURI"
					}
				]
			},
			"Action" : {
				"Attribute": 
				{
					"Id" : "action-id",
					"IncludeInResult" : true,
					"Value" : "view"
				}
			},
			"Resource" : {
				"Attributes": [
					{
						"Id" : "classification",
						"IncludeInResult" : true,
						"Value" : "CONFIDENTIAL"
					},
					{
						"Id" : "resource-id",
						"IncludeInResult" : true,
						"Value" : "document"
					}
				]
			}
		}
	}


## Response message
The response messages support the IncludeInResult triggers from the Request body to include selected attributes, Obligations with associated attributes and Advices with associated attributes in both XML and JSON output formats. The output format is steered by the _Accept_ HTTP header from the client.
_Accept_ header: What the client or _PEP_ accepts as returned Response. The following values are usable, all other will fail:
* application/xacml+json
* application/xacml+xml


### Example Response XML
	<?xml version="1.0" encoding="UTF-8"?>
	<Response xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 http://docs.oasis-open.org/xacml/3.0/xacml-core-v3-schema-wd-17.xsd">
	  <Result>
		<Decision>Permit</Decision>
		<Obligations>
		  <Obligation ObligationId="urn:omg:wtf:bbq:obligation:id">
		  <Attribute IncludeInResult="false" AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id">
			<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">view</AttributeValue>
		  </Attribute>
		  </Obligation>
		</Obligations>
		<Attributes>
		  <Attribute IncludeInResult="true" AttributeId="urn:org:apache:tomcat:user-attr:clearance">
			<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">SECRET</AttributeValue>
		  </Attribute>
		  <Attribute IncludeInResult="true" AttributeId="company">
			<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">Axiomatics</AttributeValue>
		  </Attribute>
		  <Attribute IncludeInResult="true" AttributeId="urn:org:apache:tomcat:user-role">
			<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">manager</AttributeValue>
		  </Attribute>
		  <Attribute IncludeInResult="true" AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id">
			<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">view</AttributeValue>
		  </Attribute>
		  <Attribute IncludeInResult="true" AttributeId="classification">
			<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">CONFIDENTIAL</AttributeValue>
		  </Attribute>
		  <Attribute IncludeInResult="true" AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id">
			<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">document</AttributeValue>
		  </Attribute>
		</Attributes>
	  </Result>
	</Response>

### Example Response JSON

	{
	  "Response" : {
		"Result" : {
		  "Decision" : "Permit",
		  "Obligation" : {
			"Id" : "urn:omg:wtf:bbq:obligation:id",
			"Attribute": {
				"Id": "urn:oasis:names:tc:xacml:1.0:action:action-id",
				"Value": "view"
			  }
		  },
		  "Attribute": [
			{
			  "Id": "urn:org:apache:tomcat:user-attr:clearance",
			  "Value": "SECRET"
			},
			{
			  "Id": "company",
			  "Value": "Axiomatics"
			},
			{
			  "Id": "urn:org:apache:tomcat:user-role",
			  "Value": "manager"
			},
			{
			  "Id": "urn:oasis:names:tc:xacml:1.0:action:action-id",
			  "Value": "view"
			},
			{
			  "Id": "classification",
			  "Value": "CONFIDENTIAL"
			},
			{
			  "Id": "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
			  "Value": "document"
			}
		  ]
		}
	  }
	}


## 3rd party plug-in/call-out API
General Authorization supports 3rd party call-outs per XACML Request/Response.


### Initializer
Prototype:

	int your_func_name_init(tq_xacml_callout_t *callout, int argc, char **argv);

The function is called right after starting the service, reading the configuration file and reading the policy file. Each of the configured initialization functions are called.

Tools to consider here are the genauthz_callout_get_argc(), genauthz_callout_get_argv() and genauthz_callout_set_aux() functions.


### Uninitializer
Prototype:

	void your_func_name_uninit(tq_xacml_callout_t *callout);

When the plug-in is unloaded, this callback will be triggered. This function is optional and not implemented yet.


### On rule hit callback
Prototype:

	int your_func_name_rule_hit_cb(request_mngr_t *request_mngr, tq_xacml_rule_t *trigger_by_rule, tq_xacml_callout_t *callout);

The function is called when a rule is hit. A rule could trigger multiple callouts. The request_mngr_t holds pointers to the evhtp_request_t, the XACML request and response objects, the active policy and more. Also the rule that registered the hit is based as also the context of the callout object.

The idea is that a 3rd party developer is able to have sufficient information to create a proprietary call-out and manipulate the XACML response and return. The GenAuthZ service will take care of the normalized XACML response objects and either trigger an other call-out or construct an XACML response message body and pass it to the calling user.


### Helpers functions
The call-out object tq_xacml_callout_t holds all the call-out specific data and handles to function. The safest way to extract the information is through helper functions.


#### genauthz_callout_get_argc()
Prototype:

	int genauthz_callout_get_argc(tq_xacml_callout_t *callout);

Returns the amount of arguments as configured with the _init_argv_ configuration file option in a _rule_.

#### genauthz_callout_get_argv()
Prototype:

	int genauthz_callout_get_argv(tq_xacml_callout_t *callout);

Returns the list of arguments as strings configured with the _init_argv_ configuration file option in a _rule_.

#### genauthz_callout_set_aux()
Prototype:

	void genauthz_callout_set_aux(tq_xacml_callout_t *callout, void *arg);

A void * useful to set specific data that needs to be created in the initialization phase of the plug-in and to be used per invocation of the call-out on a rule hit.

#### genauthz_callout_get_aux()
Prototype:

	void *genauthz_callout_get_aux(tq_xacml_callout_t *callout);

Retrieves the void * set via genauthz_callout_set_aux(). Useful to gain access to data set in a different phase.

