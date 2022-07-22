cd Oauth-authorization-server
./mvnw -DskipTests clean verify
cd ..
cd Oauth-resource-server/
./mvnw -DskipTests clean verify
cd ..
cd spring-security-client/
./mvnw -DskipTests clean verify
