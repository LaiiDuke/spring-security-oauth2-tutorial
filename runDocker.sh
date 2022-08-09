docker run -d --name authorization-server -p 9000:9000 authorization-server
docker run -d --name resource-server -p 8090:8090 resource-server
docker run -d --name client-server -p 8080:8080 client-server
