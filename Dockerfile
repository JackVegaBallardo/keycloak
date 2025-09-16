FROM eclipse-temurin:21-jre
WORKDIR /app
COPY target/*.jar app.jar
ENV SERVER_PORT=8080
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
