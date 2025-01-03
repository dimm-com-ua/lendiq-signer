FROM maven:3.9.9-eclipse-temurin-11 AS build

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файл pom.xml и исходный код в контейнер
COPY pom.xml .
COPY src ./src

# Собираем проект и создаем исполняемый JAR
RUN mvn clean package -DskipTests

# Создаем финальный минимальный образ
FROM alpine

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем JAR-файл из предыдущего этапа
COPY --from=build /app/target/lendiq-signer*.jar /app/lendiq-signer.jar

