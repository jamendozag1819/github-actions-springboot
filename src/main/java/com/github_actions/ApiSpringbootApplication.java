package com.github_actions;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ApiSpringbootApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApiSpringbootApplication.class, args);
		String password = "123456"; // ❌ Sonar marcará como hardcoded password
        System.out.println("Conectando con password: " + password);
	}
}
