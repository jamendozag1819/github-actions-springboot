# proyecto-final-integrador

[Ir a la documentación oficial](https://spring.io/guides)

## Enlace directo a los principales archivos

- [application.properties](src/main/resources/application.properties)
- [main](src/main/java/com/app/hotel/MainApplication.java)

## API Postman

https://documenter.getpostman.com/view/3683906/2sAXjDduw9

## Guia Videotutorial

https://www.youtube.com/watch?v=M7lhQMzzHWU

## Requerimientos principales

- Instalar GitBash
- Instalar Java JDK 17
- Instalar spring-cli https://github.com/spring-projects/spring-cli/releases

## Requerimientos secundarios

- Instalar Intellij Idea o Visual Studio Code
- Configurar git SSH en GitHub
- Instalar Laragon + MySQL
- Instalar Postman

## Pasos para ejecutar en local

```sh
# [Paso 01]
# Ejecutar script db_hotel.sql 

# [Paso 02]
# Path: src/main/resources/application.properties
# Configurar con estos datos

spring.application.name=hotel
server.port=8000
spring.datasource.url=jdbc:mysql://localhost:3306/db_hotel
spring.datasource.username=root
spring.datasource.password=
spring.jpa.hibernate.ddl-auto=update

# [Paso 03]
# Path: src/main/java/com/app/hotel/HotelApplication.java
# Clic derecho > Ejecutar run HotelApplication.java

package com.app.hotel;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class HotelApplication {

	public static void main(String[] args) {
		SpringApplication.run(HotelApplication.class, args);
	}

}
```

