#!/bin/bash

function get_oidc_server_infos {
    curl -sS $OPENID_ENDPOINT | jq $FIELD -r
}

function client_credentials {
    curl -sS --request POST --url $TOKEN_ENDPOINT \
      --header 'Accept: */*' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data client_id=$CLIENT_ID \
      --data client_secret=$CLIENT_SECRET \
      --data grant_type=client_credentials \
 | jq $FIELD -r
}

function token_exchange {
    curl -sS --request POST --url $TOKEN_ENDPOINT \
      --header 'Accept: */*' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data client_id=$CLIENT_ID \
      --data client_secret=$CLIENT_SECRET \
      --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
      --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
      --data subject_token=$ACCESS_TOKEN \
      --data subject_issuer=$ISSUER \
 | jq $FIELD -r

}

function resource_owner_password_grant {
    curl -sS --request POST --url $TOKEN_ENDPOINT \
      --header 'Accept: */*' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data client_id=$CLIENT_ID \
      --data client_secret=$CLIENT_SECRET \
      --data username=$USERNAME \
      --data password=$PASSWORD \
      --data scope=$SCOPE \
      --data grant_type=password \
 | jq $FIELD -r

}

function refresh_token {
    curl -sS --request POST --url $TOKEN_ENDPOINT \
      --header 'Accept: */*' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data client_id=$CLIENT_ID \
      --data client_secret=$CLIENT_SECRET \
      --data refresh_token=$REFRESH_TOKEN \
      --data grant_type=refresh_token \
 | jq $FIELD -r

}

function token_introspect {
    curl -sS --request POST --url $TOKEN_INTROSPECTION_ENDPOINT \
      --header 'Accept: */*' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --user $CLIENT_ID:$CLIENT_SECRET \
      --data token=$ACCESS_TOKEN \
 | jq $FIELD -r
}

function user_info {
    curl -sS --request GET --url $USERINFO_ENDPOINT \
      --header 'Accept: */*' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --header "Authorization: Bearer $ACCESS_TOKEN"\
 | jq $FIELD -r
}

function device_code {
  curl -sS --request POST --url $DEVICE_ENDPOINT \
      --header 'Accept: */*' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data client_id=$CLIENT_ID \
      --data client_secret=$CLIENT_SECRET \
  | jq $FIELD -r
}

function poll_token {
  curl -sS --request POST --url $TOKEN_ENDPOINT \
      --header 'Accept: */*' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data client_id=$CLIENT_ID \
      --data client_secret=$CLIENT_SECRET \
      --data-urlencode device_code=$DEVICE_CODE \
      --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  | jq $FIELD -r
}

function implicit_grant {
  echo "OPEN THIS URI IN YOUR WEB BROWSER"
  echo "$AUTHORIZATION_ENDPOINT?client_id=$CLIENT_ID&scope=$SCOPE&response_type=token&response_mode=fragment&redirect_uri=$REDIRECT_URI"

  echo "-- LISTENING ON PORT 8080 FOR A REDIRECT"

  # listening for a reponse
  # from : https://stackoverflow.com/questions/26455434/create-a-minimum-rest-web-server-with-netcat-nc
  rm -f /tmp/out
  mkfifo /tmp/out
  trap "rm -f /tmp/out" EXIT
  cat /tmp/out | nc -lp 8080 > >( # parse the netcat output, to build the answer redirected to the pipe "/tmp/out".
    export REQUEST=
    while read line
    do
      line=$(echo "$line" | tr -d '[\r\n]')
      if echo "$line" | grep -qE '^GET /' # if line starts with "GET /"
      then
        REQUEST=$(echo "$line" | cut -d ' ' -f2) # extract the request
      elif [ "x$line" = x ] # empty line / end of request
      then
        HTTP_200="HTTP/1.1 200 OK"
        HTTP_LOCATION="Location:"
        HTTP_404="HTTP/1.1 404 Not Found"
        # call a script here
        # Note: REQUEST is exported, so the script can parse it (to answer 200/403/404 status code + content)
        if echo $REQUEST | grep -qE '^/'
        then
          # https://riptutorial.com/bash/example/29664/request-method--get
          ACCESS_TOKEN=$(echo "$REQUEST" | sed -n 's/^.*access_token=\([^&]*\).*$/\1/p')
          HTML="<html><head><body></body><script>\
                 var paramStr = window.location.hash.substring(1);\
                 if(paramStr == \"\"){\
                    paramStr = window.location.search.substring(1);\
                 }\
                 var params = {} \
                 var vars = paramStr.split('&');
                 for (var i = 0; i < vars.length; i++) {
                   var pair = vars[i].split('=');
                   params[pair[0]] = decodeURIComponent(pair[1]);
                 }
                 document.write(JSON.stringify(params));
                 </script></html>"
          printf "%s\n%s %s\n\n%s\n" "$HTTP_200" "$HTTP_LOCATION" $REQUEST $HTML > /tmp/out
          exit 0
        fi
      fi
    done
    exit 1
  )
}

function authorization_code_grant {
  echo "OPEN THIS URI IN YOUR WEB BROWSER"
  echo "$AUTHORIZATION_ENDPOINT?client_id=$CLIENT_ID&scope=$SCOPE&response_type=code&response_mode=fragment&redirect_uri=$REDIRECT_URI"

  echo "-- LISTENING ON PORT 8080 FOR A REDIRECT"

  # listening for a reponse
  # from : https://stackoverflow.com/questions/26455434/create-a-minimum-rest-web-server-with-netcat-nc
  rm -f /tmp/out
  mkfifo /tmp/out
  trap "rm -f /tmp/out" EXIT
  cat /tmp/out | nc -lp 8080 > >( # parse the netcat output, to build the answer redirected to the pipe "/tmp/out".
    export REQUEST=
    while read line
    do
      line=$(echo "$line" | tr -d '[\r\n]')
      if echo "$line" | grep -qE '^GET /' # if line starts with "GET /"
      then
        REQUEST=$(echo "$line" | cut -d ' ' -f2) # extract the request
      elif [ "x$line" = x ] # empty line / end of request
      then
        HTTP_200="HTTP/1.1 200 OK"
        HTTP_LOCATION="Location:"
        HTTP_404="HTTP/1.1 404 Not Found"
        # call a script here
        # Note: REQUEST is exported, so the script can parse it (to answer 200/403/404 status code + content)
        if echo $REQUEST | grep -qE '^/'
        then
          # https://riptutorial.com/bash/example/29664/request-method--get
          ACCESS_TOKEN=$(echo "$REQUEST" | sed -n 's/^.*access_token=\([^&]*\).*$/\1/p')
          HTML="<html><head><body></body><script>\
                 var paramStr = window.location.hash.substring(1);\
                 if(paramStr == \"\"){\
                    paramStr = window.location.search.substring(1);\
                 }\
                 var params = {} \
                 var vars = paramStr.split('&');
                 for (var i = 0; i < vars.length; i++) {
                   var pair = vars[i].split('=');
                   params[pair[0]] = decodeURIComponent(pair[1]);
                 }
                 document.write(JSON.stringify(params));
                 </script></html>"
          printf "%s\n%s %s\n\n%s\n" "$HTTP_200" "$HTTP_LOCATION" $REQUEST $HTML > /tmp/out
          exit 0
        fi
      fi
    done
    exit 1
  )
}

function auth_code {
    curl -sS --request POST --url $TOKEN_ENDPOINT \
      --header 'Accept: */*' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data client_id=$CLIENT_ID \
      --data client_secret=$CLIENT_SECRET \
      --data-urlencode code=$AUTHORIZATION_CODE \
      --data redirect_uri=$REDIRECT_URI \
      --data grant_type=authorization_code \
 | jq $FIELD -r 
}

function end_session {
    curl -sS --request POST --url $END_SESSION_ENDPOINT \
      --header 'Accept: */*' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --header 'Authorization: Bearer $ACCESS_TOKEN' \
      --data client_id=$CLIENT_ID \
      --data client_secret=$CLIENT_SECRET \
      --data refresh_token=$REFRESH_TOKEN \
 | jq $FIELD -r
}


function show_help {

echo "PLEASE-OPEN.IT BASH CLIENT"
echo "SYNOPSIS"
echo ""
echo "oidc-client.sh --operation OP --openid-endpoint [--authorization-endpoint --token-introspection-endpoint --token-endpoint --end-session-endpoint --device-authorization-endpoint] --client-id --client-secret --username --password --scope --access-token --refresh-token --issuer --redirect-uri --authorization-code --device-code --field "



echo "DESCRIPTION"
echo ""
echo "This script is a wrapper over oauth2/openid connect"

echo "OPTIONS"
echo "  --operation in : "
echo "    get_oidc_server_infos"
echo "    client_credentials"
echo "    resource_owner_password_grant"
echo "    end_session"
echo "    refresh_token"
echo "    token_exchange"
echo "    implicit_grant"
echo "    authorization_code_grant"
echo "    auth_code"
echo "    token_introspect"
echo "    user_info"
echo "    device_code"
echo "    poll_token"
echo ""
echo " --field : filter for JQ"
echo ""
echo "More : "
}

PARAMS=""
while (( "$#" )); do
  case "$1" in
    --help)
      show_help
      shift
      ;;
    --operation)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        OPERATION=$2
        shift 2
      else
        echo "Error: Argument for $1 is missing" >&2
        exit 1
      fi
      ;;
    --openid-endpoint)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        OPENID_ENDPOINT=$2
        shift 2
      fi
      ;;
    --authorization-endpoint)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        AUTHORIZATION_ENDPOINT=$2
        shift 2
      fi
      ;;
    --token-introspection-endpoint)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        TOKEN_INTROSPECTION_ENDPOINT=$2
        shift 2
      fi
      ;;
    --device-authorization-endpoint)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        DEVICE_ENDPOINT=$2
        shift 2
      fi
      ;;
    --token-endpoint)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        TOKEN_ENDPOINT=$2
        shift 2
      fi
      ;;
    --client-id)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        CLIENT_ID=$2
        shift 2
      fi
      ;;
    --client-secret)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        CLIENT_SECRET=$2
        shift 2
      fi
      ;;
    --username)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        USERNAME=$2
        shift 2
      fi
      ;;
    --password)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        PASSWORD=$2
        shift 2
      fi
      ;;
    --scope)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        SCOPE=$2
        shift 2
      fi
      ;;
    --access-token)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        ACCESS_TOKEN=$2
        shift 2
      fi
      ;;
    --refresh-token)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        REFRESH_TOKEN=$2
        shift 2
      fi
      ;;
    --end-session-endpoint)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        END_SESSION_ENDPOINT=$2
        shift 2
      fi
      ;;
    --issuer)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        ISSUER=$2
        shift 2
      fi
      ;;
    --redirect-uri)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        REDIRECT_URI=$2
        shift 2
      fi
      ;;
    --authorization-code)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        AUTHORIZATION_CODE=$2
        shift 2
      fi
      ;;
    --device-code)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        DEVICE_CODE=$2
        shift 2
      fi
      ;;
    --field)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        FIELD=$2
        shift 2
      fi
      ;;
    -*|--*=) # unsupported flags
      echo "Error: Unsupported flag $1" >&2
      exit 1
      ;;
    *) # preserve positional arguments
      PARAMS="$PARAMS $1"
      shift
      ;;
  esac
done


case "$OPERATION" in
  get_oidc_server_infos)
    if [ -z "$OPENID_ENDPOINT" ]; then
      echo "Error: --openid-endpoint is missing" >&2
      exit 1
    fi
    get_oidc_server_infos
    ;;

  client_credentials)
    if [ -z "$OPENID_ENDPOINT" ] && [ -z "$TOKEN_ENDPOINT" ]; then
      echo "Error: --token-endpoint is missing, you can also use --openid-endpoint" >&2
      exit 1
    fi
    if [ -z "$CLIENT_ID" ] && [ -z "$CLIENT_SECRET" ]; then
      echo "Error: --client-id or --client-secret is missing" >&2
      exit 1
    fi
    if [ -z "$TOKEN_ENDPOINT" ]; then
      TOKEN_ENDPOINT=$(curl -sS $OPENID_ENDPOINT | jq .token_endpoint -r)
    fi
    client_credentials
    ;;
  resource_owner_password_grant)
    if [ -z "$OPENID_ENDPOINT" ] && [ -z "$TOKEN_ENDPOINT" ]; then
      echo "Error: --token-endpoint is missing, you can also use --openid-endpoint" >&2
      exit 1
    fi
    if [ -z "$CLIENT_ID" ] && [ -z "$CLIENT_SECRET" ]; then
      echo "Error: --client-id or --client-secret is missing" >&2
      exit 1
    fi
    if [ -z "$USERNAME" ] && [ -z "$PASSWORD" ]; then
      echo "Error: --username or --password is missing" >&2
      exit 1
    fi
    if [ -z "$TOKEN_ENDPOINT" ]; then
      TOKEN_ENDPOINT=$(curl -sS $OPENID_ENDPOINT | jq .token_endpoint -r)
    fi
    resource_owner_password_grant
    ;;
  end_session)
    if [ -z "$OPENID_ENDPOINT" ] && [ -z "$END_SESSION_ENDPOINT" ]; then
      echo "Error: --end-session-endpoint is missing, you can also use --openid-endpoint" >&2
      exit 1
    fi
    if [ -z "$CLIENT_ID" ] && [ -z "$CLIENT_SECRET" ]; then
      echo "Error: --client-id or --client-secret is missing" >&2
      exit 1
    fi
    if [ -z "$ACCESS_TOKEN" ]; then
      echo "Error: --access-token is missing" >&2
      exit 1
    fi
    if [ -z "$REFRESH_TOKEN" ]; then
      echo "Error: --refresh-token is missing" >&2
      exit 1
    fi
    if [ -z "$END_SESSION_ENDPOINT" ]; then
      END_SESSION_ENDPOINT=$(curl -sS $OPENID_ENDPOINT | jq .end_session_endpoint -r)
    fi
    end_session
    ;;
  refresh_token)
    if [ -z "$OPENID_ENDPOINT" ] && [ -z "$TOKEN_ENDPOINT" ]; then
      echo "Error: --token-endpoint is missing, you can also use --openid-endpoint" >&2
      exit 1
    fi
    if [ -z "$CLIENT_ID" ] && [ -z "$CLIENT_SECRET" ]; then
      echo "Error: --client-id or --client-secret is missing" >&2
      exit 1
    fi
    if [ -z "$REFRESH_TOKEN" ]; then
      echo "Error: --refresh-token is missing" >&2
      exit 1
    fi
    if [ -z "$TOKEN_ENDPOINT" ]; then
      TOKEN_ENDPOINT=$(curl -sS $OPENID_ENDPOINT | jq .token_endpoint -r)
    fi
    refresh_token
    ;;
  token_exchange)
    if [ -z "$OPENID_ENDPOINT" ] && [ -z "$TOKEN_ENDPOINT" ]; then
      echo "Error: --token-endpoint is missing, you can also use --openid-endpoint" >&2
      exit 1
    fi
    if [ -z "$CLIENT_ID" ] && [ -z "$CLIENT_SECRET" ]; then
      echo "Error: --client-id or --client-secret is missing" >&2
      exit 1
    fi
    if [ -z "$ACCESS_TOKEN" ]; then
      echo "Error: --access-token is missing" >&2
      exit 1
    fi
    if [ -z "$ISSUER" ]; then
      echo "Error: --issuer is missing" >&2
      exit 1
    fi
    if [ -z "$TOKEN_ENDPOINT" ]; then
      TOKEN_ENDPOINT=$(curl -sS $OPENID_ENDPOINT | jq .token_endpoint -r)
    fi
    token_exchange
    ;;
  implicit_grant)
    if [ -z "$OPENID_ENDPOINT" ] && [ -z "$AUTHORIZATION_ENDPOINT" ]; then
      echo "Error: --authorization-endpoint is missing, you can also use --openid-endpoint" >&2
      exit 1
    fi
    if [ -z "$CLIENT_ID" ]; then
      echo "Error: --client-id is missing" >&2
      exit 1
    fi
    if [ -z "$REDIRECT_URI" ]; then
      echo "Error: --redirect-uri is missing" >&2
      exit 1
    fi
    if [ -z "$AUTHORIZATION_ENDPOINT" ]; then
      AUTHORIZATION_ENDPOINT=$(curl -sS $OPENID_ENDPOINT | jq .authorization_endpoint -r)
    fi
    implicit_grant
    ;;
  authorization_code_grant)
    if [ -z "$OPENID_ENDPOINT" ] && [ -z "$AUTHORIZATION_ENDPOINT" ]; then
      echo "Error: --authorization-endpoint is missing, you can also use --openid-endpoint" >&2
      exit 1
    fi
    if [ -z "$CLIENT_ID" ]; then
      echo "Error: --client-id is missing" >&2
      exit 1
    fi
    if [ -z "$REDIRECT_URI" ]; then
      echo "Error: --redirect-uri is missing" >&2
      exit 1
    fi
    if [ -z "$AUTHORIZATION_ENDPOINT" ]; then
      AUTHORIZATION_ENDPOINT=$(curl -sS $OPENID_ENDPOINT | jq .authorization_endpoint -r)
    fi
    authorization_code_grant
    ;;
  auth_code)
    if [ -z "$OPENID_ENDPOINT" ] && [ -z "$TOKEN_ENDPOINT" ]; then
      echo "Error: --token-endpoint is missing, you can also use --openid-endpoint" >&2
      exit 1
    fi
    if [ -z "$CLIENT_ID" ]; then
      echo "Error: --client-id is missing" >&2
      exit 1
    fi
    if [ -z "$REDIRECT_URI" ]; then
      echo "Error: --redirect-uri is missing" >&2
      exit 1
    fi
    if [ -z "$AUTHORIZATION_CODE" ]; then
      echo "Error: --authorization-code is missing" >&2
      exit 1
    fi
    if [ -z "$TOKEN_ENDPOINT" ]; then
      TOKEN_ENDPOINT=$(curl -sS $OPENID_ENDPOINT | jq .token_endpoint -r)
    fi
    auth_code
    ;;
  token_introspect)
    if [ -z "$OPENID_ENDPOINT" ] && [ -z "$TOKEN_INTROSPECTION_ENDPOINT" ]; then
      echo "Error: --token-introspection-endpoint is missing, you can also use --openid-endpoint" >&2
      exit 1
    fi
    if [ -z "$CLIENT_ID" ] && [ -z "$CLIENT_SECRET" ]; then
      echo "Error: --client-id or --client-secret is missing" >&2
      exit 1
    fi
    if [ -z "$ACCESS_TOKEN" ]; then
      echo "Error: --access-token is missing" >&2
      exit 1
    fi
    if [ -z "$TOKEN_INTROSPECTION_ENDPOINT" ]; then
      TOKEN_INTROSPECTION_ENDPOINT=$(curl -sS $OPENID_ENDPOINT | jq .introspection_endpoint -r)
    fi
    token_introspect
    ;;

  user_info)
    if [ -z "$OPENID_ENDPOINT" ] && [ -z "$USERINFO_ENDPOINT" ]; then
      echo "Error: --userinfo-endpoint is missing, you can also use --openid-endpoint" >&2
      exit 1
    fi
    if [ -z "$ACCESS_TOKEN" ]; then
      echo "Error: --access-token is missing" >&2
      exit 1
    fi
    if [ -z "$USERINFO_ENDPOINT" ]; then
      USERINFO_ENDPOINT=$(curl -sS $OPENID_ENDPOINT | jq .userinfo_endpoint -r)
    fi
    user_info
    ;;
  device_code)
    if [ -z "$OPENID_ENDPOINT" ] && [ -z "$DEVICE_ENDPOINT" ]; then
      echo "Error: --device-endpoint is missing, you can also use --openid-endpoint" >&2
      exit 1
    fi
    if [ -z "$CLIENT_ID" ]; then
      echo "Error: --client-id is missing" >&2
      exit 1
    fi
    if [ -z "$CLIENT_SECRET" ]; then
      echo "Error: --client-secret is missing" >&2
      exit 1
    fi
    if [ -z "$DEVICE_ENDPOINT" ]; then
      DEVICE_ENDPOINT=$(curl -sS $OPENID_ENDPOINT | jq .device_authorization_endpoint -r)
    fi
    device_code
    ;;
  poll_token)
    if [ -z "$OPENID_ENDPOINT" ] && [ -z "$TOKEN_ENDPOINT" ]; then
      echo "Error: --token-endpoint is missing, you can also use --openid-endpoint" >&2
      exit 1
    fi
    if [ -z "$CLIENT_ID" ]; then
      echo "Error: --client-id is missing" >&2
      exit 1
    fi
    if [ -z "$CLIENT_SECRET" ]; then
      echo "Error: --client-secret is missing" >&2
      exit 1
    fi
    if [ -z "$DEVICE_CODE" ]; then
      echo "Error: --device-code is missing" >&2
      exit 1
    fi
    if [ -z "$TOKEN_ENDPOINT" ]; then
      TOKEN_ENDPOINT=$(curl -sS $OPENID_ENDPOINT | jq .token_endpoint -r)
    fi
    poll_token
    ;;
    *)
    echo "unsupported operation"
    exit 1
    ;;
  
esac

