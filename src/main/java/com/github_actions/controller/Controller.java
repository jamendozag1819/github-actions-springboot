package com.github_actions.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {
	private final String PASSWORD = "12345";

	@GetMapping("/")
	public String mensaje() {
		return "Prueba controller";
	}

	@GetMapping("/usuario")
	public String getUser(@RequestParam String id) {
		String query = "SELECT * FROM users WHERE id = " + id; // SQL Injection
		return query;
	}

	public int calcularPromedio(int suma, int cantidad) {
		return suma / cantidad; // BUG: posible división entre cero
	}

	public String obtenerLongitud(String texto) {
		return "Longitud: " + texto.length(); // BUG: texto puede ser null
	}

	public boolean validar(int x) {
		if (x > 0 || x < 0) { // BUG: siempre verdadero
			return true;
		}
		return false;
	}
	
	public void procesar() {
	    System.out.println("a");
	    System.out.println("b");
	    System.out.println("c");
	    System.out.println("d");
	    System.out.println("e");
	    System.out.println("f");
	    System.out.println("g"); // 7+ líneas sin sentido → code smell
	}


}
