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

}
