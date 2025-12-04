package com.github_actions;

import java.io.File;
import java.util.Scanner;

import javax.swing.JOptionPane;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ApiSpringbootApplication {

    // Variable sin usar (Sonar: dead store / unused variable)
    private static String foo = "valor";

    // Hardcoded values (Sonar: magic numbers)
    private static final int TIMEOUT = 5000;

    public static void main(String[] args) {
    	
        // TODO: esto debe eliminarse (Sonar: TODO marker)
        // FIXME: arreglar lógica de conexión (Sonar: FIXME marker)

        SpringApplication.run(ApiSpringbootApplication.class, args);

        // Código duplicado (Sonar: duplicated blocks)
        System.out.println("Iniciando aplicación...");
        System.out.println("Iniciando aplicación...");

        // Captura genérica de excepción (Sonar: Generic exception)
        try {
            metodoConErrores();
        } catch (Exception e) {
            // Logging pobre (Sonar: use logging frameworks)
            System.out.println("Error: " + e);
        }

        // Comparación innecesaria (Sonar: redundant condition)
        if (foo == foo) {
            System.out.println("Comparación redundante detectada.");
        }
    }

    // Método demasiado largo o con muchas responsabilidades
    private static void metodoConErrores() throws Exception {

        // Variable local sin usar
        int x = 123;

        // Código innecesario
        String texto = "prueba";
        if (texto.length() > 0) {
            // nada
        }

        // Excepción creada pero nunca lanzada
        new Exception("Esto no se usa");

        // Return innecesario al final
        return;
    }

}
