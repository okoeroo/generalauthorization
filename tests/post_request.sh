#!/bin/bash

curl -vvvvv -H "Accept: application/xacml+xml" -d@xacml_request.xml 127.0.0.1:8081/authorization/pdp/
exit $?
