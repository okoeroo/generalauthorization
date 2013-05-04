# General Authorization

### Faster than light XACML 3.0 REST service
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
* libevhtp (version 1.2.0 or up)
    Goto: https://github.com/ellzey/libevhtp
    Dependencies of libevhtp:
    * libevent2 (with OpenSSL)
        Goto: http://libevent.org/
    * OpenSSL
        Goto: http://www.openssl.org/
* libconfuse
    Goto: http://www.nongnu.org/confuse/
* libxml2
    Goto: http://www.xmlsoft.org/


