#!/bin/bash

DEFAULT="localhost"

usage() {
    echo "post_request.sh <xml|json> [host; default: $DEFAULT]"
}

if [ -z "$1" ]; then
    usage
    exit 1
fi

if [ -n "$2" ]; then
    HOST="$2"
else
    HOST=$DEFAULT
fi

if [ "json" = "$1" ]; then
    curl -vvvvv -H "Accept: application/xacml+json" \
                -H "Content-Type: application/xacml+json" \
                -d@xacml_request.json http://${HOST}:8081/authorization/pdp/
    exit $?
elif [ "xmljson" = "$1" ]; then
    curl -vvvvv -H "Accept: application/xacml+json" \
                -H "Content-Type: application/xacml+xml" \
                -d@xacml_request.xml http://${HOST}:8081/authorization/pdp/
    exit $?
elif [ "jsonxml" = "$1" ]; then
    curl -vvvvv -H "Accept: application/xacml+xml" \
                -H "Content-Type: application/xacml+json" \
                -d@xacml_request.json http://${HOST}:8081/authorization/pdp/
    exit $?
else
    curl -vvvvv -H "Accept: application/xacml+xml" \
                -H "Content-Type: application/xacml+xml" \
                -d@xacml_request.xml http://${HOST}:8081/authorization/pdp/
    exit $?
fi
