FROM ubuntu-latest
EXPOSE 8080
ADD target/api-springboot-0.0.1.jar api-springboot-new.jar
ENTRYPOINT [ "java", "-jar","/api-springboot-new.jar" ]