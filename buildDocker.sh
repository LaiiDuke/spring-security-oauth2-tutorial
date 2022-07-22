cd Oauth-authorization-server
docker build -t authorization-server .
cd ..
cd Oauth-resource-server/
docker build -t resource-server .
cd ..
cd spring-security-client/
docker build -t client-server .