FROM adoptopenjdk/openjdk11
COPY . .
RUN ./mvnw -DskipTests clean verify
CMD java -jar target/spring-security-client-0.0.1-SNAPSHOT.jar