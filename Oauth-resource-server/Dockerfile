FROM adoptopenjdk/openjdk11
COPY . .
RUN ./mvnw -DskipTests clean verify
CMD java -jar target/Oauth-resource-server-0.0.1-SNAPSHOT.jar