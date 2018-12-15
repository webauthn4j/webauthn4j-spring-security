FROM openjdk:8-jdk AS build-env

LABEL maintainer="Yoshikazu Nojima <mail@ynojima.net>"

ADD . /workspace
WORKDIR /workspace
RUN ./gradlew build -x test


FROM openjdk:8-jre

LABEL maintainer="Yoshikazu Nojima <mail@ynojima.net>"

COPY --from=build-env /workspace/samples/javaconfig/webauthn/spa/build/libs/spring-security-webauthn-sample-spa.jar /opt/spring-security-webauthn/spring-security-webauthn-sample-spa.jar

WORKDIR /opt/spring-security-webauthn
CMD ["java", "-XX:+UnlockExperimentalVMOptions", "-XX:+UseCGroupMemoryLimitForHeap", "-jar", "/opt/spring-security-webauthn/spring-security-webauthn-sample-spa.jar"]

EXPOSE 8080
