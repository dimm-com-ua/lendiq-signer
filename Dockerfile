FROM maven:3.9.9-eclipse-temurin-11 AS build

WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package -DskipTests

FROM alpine

WORKDIR /app

COPY --from=build /app/target/lendiq-signer*.jar /app/lendiq-signer.jar

