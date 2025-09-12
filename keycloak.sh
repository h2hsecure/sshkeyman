export KEYCLOAK_HOST=<your_keycloak_server_host>
export REALM_NAME=<your_keycloak_server_realm>
export ADMIN_NAME=test
export ADMIN_PASSWORD=test

curl https://${KEYCLOAK_HOST}/auth/realms/${REALM_NAME}/protocol/openid-connect/token \
    -d "client_id=admin-cli" \
    -d "username=$ADMIN_NAME" \
    -d "password=$ADMIN_PASSWORD" \
    -d "grant_type=password"


curl -X GET "https://${KEYCLOAK_HOST}/auth/admin/realms/${REALM_NAME}/users/?username=${USERNAME}&exact=true" -H "Content-Type: application/json" -H "Authorization: bearer $ACCESS_TOKEN"