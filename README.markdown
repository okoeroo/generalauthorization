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

## 3rd-party plug-in support

It offers the opportunity to call-out to a 3rd-party plug-in. The plug-in
will be triggered when an XACML Request is matched in an XACML policy rule that
is configured to call-out to the plug-in. The plug-in has the opportunity to
manipulate the XACML Response, but also all the other elements. Even the loaded
XACML policy if you wish to do so.

An example 3rd-party plug-in can be found here:
https://github.com/okoeroo/genauthz_simple_curl_call

For a Nikhef related project with MPI (Nijmegen) the following plug-in was developed: 
https://github.com/okoeroo/genauthz_htaccess

## ...but why?
I had an itch to scratch and the saml2-xacml2 PDP based on gSOAP didn't perform
to my satisfaction and wanted experience the do's and don'ts of creating a well
performing service.

## Current state
Work in progress, but functional and well performing

## Implements the following standards(*)
* XACML 3 core spec: http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.pdf
* XACML 3 REST profile: http://docs.oasis-open.org/xacml/xacml-rest/v1.0/xacml-rest-v1.0.pdf
* XACML 3 JSON Request/Response: https://www.oasis-open.org/committees/document.php?document_id=47775
* Accept and Content-Type headers: http://tools.ietf.org/html/draft-sinnema-xacml-media-type-05

(*) To a certain degree. The policy engine does not fully implement the spec.

## Known BUGS
* The _syslog_ section's _options_ doesn't work reliably on all platforms (libconfuse problem).
* The _composition_ element in the policy file doesn't work yet.
* The _plugin_uninit_ element in the policy file doesn't work yet.

## Release Notes

### Version [current]
* Removed unused defines
* Fixed the Content-Type on the return message. It now indicates the proper xml or json based string according to http://tools.ietf.org/html/draft-sinnema-xacml-media-type-05
* Added reference to the GenAuthz htaccess plug-in in the README file
* Added release notes to the README file
* Cleanup output to the shell
* Added -v/--verbose commandline options. Set it twice to print all the syslog info to stderr.
* Added -f/--foreground to start the service without daemonization.
* Added a init.d script supporting Debian, SuSe and Red Hat explicitly.

### Version 0.1.0
* Updated tree.h and queue.h files from *BSD. Gives extra compiler warnings, but are understood and ignoreable
* README file specifies which specifications/standard are supported
* Updated mediatype support
* Fixed the evaluation code. It evaluated badly

### Version 0.0.13
* Avoid the distribution of the autoheader generated files

### Version 0.0.12
* Significant README file extension
* Added SSL support on all the interfaces (PDP, Control and PAP)

### Version 0.0.11
* Fixed the argc/argv mis-alignment to plug-ins.
* Rewritten the PDP code to be more maintainable.
* Added the libevhtp pause/resume calls in the PDP (aids in high concurreny cases)

### Version 0.0.10
* Added all stack protectors
* Added pkgconfig file for libgenauthz_core (tested with an external plug-in)

### Version 0.0.9
* Split the service into a main executable and a libgenauthz_core.{so,dylib} core library that can be linked to by the plugins. This is not needed on OSX, but required on Linux.
* Fixed headerfile distribution. Needed headers are installed in /usr{/local}/include/genauthz/
* Now "make distcheck" clean

### Version 0.0.8
* Exposing the dlopen/dlsym related error in the logfile.
* Changed the header file inclusion to a more simple and flat approach

### Version 0.0.7
* Implemented an example plug-in.
* Extended the policy configuration file options to configure the initialization, uninitialization and on-rule-hit callbacks.

### Version 0.0.6
* Added 3rd party callout support which is called on a rule hit.

### Version 0.0.5
* Fixed a listener and service config definition problem. The config file didn't resolve to the intended threadpool state
* Added per rule hit counter
* Added lots of compiler flags to catch mistakes
* Builds without compiler warnings with lots of flags enabled
* Fixed conversion problems and potential segfaults
* Removed unused code
* Catched several blackholed return values
* added autoconf compiler flag checks.

### Version 0.0.4
* Added PAP interface to query the active policy
* Added Control interface to query the active state and service usage 

### Version 0.0.3
* Added libjansson to parse and process JSON input and output
* Accepting mediatypes specified in http://tools.ietf.org/html/draft-sinnema-xacml-media-type-05

### Version 0.0.2
* Documentation written for most details at this moment in time.
* Supporting Advices, IncludeInResult and Obligations as output elements.

### Version 0.0.1
* Basic XACML PDP based on XML using libxml2. Policy evaluation not functional

## Dependencies
* libevhtp (version 1.2.0 or up): https://github.com/ellzey/libevhtp
* libconfuse: http://www.nongnu.org/confuse/
* libxml2: http://www.xmlsoft.org/
* libjansson: http://www.digip.org/jansson/

### Dependencies of libevhtp:
* libevent2: (with OpenSSL): http://libevent.org/
* OpenSSL: http://www.openssl.org/
* pthreads: http://en.wikipedia.org/wiki/POSIX_Threads

### Dependency hints
Libevhtp is very picky on the OpenSSL version. Use a very recent version of 0.9.8 or anything beyond OpenSSL 1.0.0 version.
To be able to build libevhtp to use a custom OpenSSL local build do the following:

0. cd libconfuse*; ./configure --enable-shared && make && make install
1. export CFLAGS="-I/usr/local/ssl/include"
2. export LDFLAGS="-L/usr/local/ssl/lib"
3. cd libevent2; ./configure && make && make install
4. cd libevhtp; git checkout 1.2.5
5. cmake -DEVHTP_BUILD_SHARED:STRING=ON -DCMAKE_INCLUDE_PATH=/usr/local/ssl/include/ -DCMAKE_LIBRARY_PATH=/usr/local/ssl/lib .

Don't forget the libconfuse to build as a shared object:
* cd libconfuse; ./configure --enable-shared && make && make install

## Commandline arguments
* `--conf <configuration file>`: The configuration file. The policy file is configured here.
* `-f | --foreground`: Let the service run in the foreground. Will daemonize by default.
* `-v | --verbose`: Add more output when the service start. Set twice to print all the syslog information on stderr.

## Go with the Flow
There are two types of phases, the start up phase and running each of the URI triggers.

1. Start up time
    1. Load configuration file
    2. Setup Syslog details
    3. Bind the sockets, when running as root, downgrade to __nobody:nogroup__
    4. Load the XACML policy file
    5. For each of the call-outs, load the shared object file and run the _func_name_init_

2. PDP
    1. Wait for XACML 3 REST profile request in XML and JSON
        1. Receiving data (post-SSL) in event buffers and reroute it to the threadpool (libevhtp/openssl/libevent2)
        2. Call the HTTP request handler (libevhtp)
    2. Build a request_mngr_t struct (GenAuthZ)
        1. Check the HTTP method and the Accept + Content-Type data and select the XML or JSON parser
        2. Normalize the XACML XML or JSON input to GenAuthZ objects
        3. XACML policy evaluation based on the policy configuration file.
        4. On rule hit
            1. Set the static result information, i.e. setting the Decision, Obligations, Advices and IncludeInResult attributes.
            2. Execute the _rule_hit_cb_ callbacks which are defined (if any) per rule. All the previously set static results can be manipulated.
        5. Transform the normalized XACML to JSON or XML, based on the Accept header of the request.
    3. Transfer the HTTP response (libevhtp/openssl/libevent2)

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

	char **genauthz_callout_get_argv(tq_xacml_callout_t *callout);

Returns the list of arguments as strings configured with the _init_argv_ configuration file option in a _rule_.

#### genauthz_callout_set_aux()
Prototype:

	void genauthz_callout_set_aux(tq_xacml_callout_t *callout, void *arg);

A void * useful to set specific data that needs to be created in the initialization phase of the plug-in and to be used per invocation of the call-out on a rule hit.

#### genauthz_callout_get_aux()
Prototype:

	void *genauthz_callout_get_aux(tq_xacml_callout_t *callout);

Retrieves the void * set via genauthz_callout_set_aux(). Useful to gain access to data set in a different phase.

## Example plug-in

	#include <stdio.h>
	#include <string.h>
	#include <genauthz/genauthz_plugin.h>
	
	int  example_plugin_init(tq_xacml_callout_t *);
	void example_plugin_uninit(tq_xacml_callout_t *);
	int  example_plugin_rule_hit(request_mngr_t *, tq_xacml_rule_t *, tq_xacml_callout_t *);
	
	int
	example_plugin_init(tq_xacml_callout_t *callout) {
		int i;
		int argc;
		char **argv;
		char *test;
	
		argc = genauthz_callout_get_argc(callout);
		argv = genauthz_callout_get_argv(callout);
	
		for (i = 0; i < argc; i++) {
			printf("Argv[%d]: %s\n", i, argv[i]);
		}
	
		test = strdup("w00t w00t");
		genauthz_callout_set_aux(callout, test);
		return 0;
	}
	
	void
	example_plugin_uninit(tq_xacml_callout_t *callout) {
		printf("%s\n", (char *)genauthz_callout_get_aux(callout));
		return;
	}
	
	int
	example_plugin_rule_hit(request_mngr_t *request_mngr,
							tq_xacml_rule_t *rule,
							tq_xacml_callout_t *callout) {
		printf("Rule \"%s\" hit! -- %s\n", rule->name, __func__);
	
		print_normalized_xacml_request(request_mngr->xacml_req);
		print_normalized_xacml_response(request_mngr->xacml_res);
		print_loaded_policy(request_mngr->app->parent->xacml_policy);
	
		printf("%s\n", (char *)genauthz_callout_get_aux(callout));
	
		return 0;
	}


## Example Makefile.am

	lib_LTLIBRARIES = libgenauthz_example.la
	libgenauthz_example_la_SOURCES = example_main.c
	libgenauthz_example_la_LDFLAGS = -lgenauthz_core

