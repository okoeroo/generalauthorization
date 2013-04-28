#!/bin/bash

if [ -n "$1" ]; then
    HOST="$1"
else
    HOST="127.0.0.1"
fi

curl -vvvvv -H "Accept: application/xacml+xml" -d@xacml_request.xml ${HOST}:8081/authorization/pdp/
exit $?
