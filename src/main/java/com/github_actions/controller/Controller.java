package com.github_actions.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {

	@GetMapping("/")
	public String mensaje() {
		return "Prueba controller";
	}
	
	@GetMapping("/vuln")
	public String insecure(@RequestParam String input){
	    return "Result: " + input; // posible XSS
	}

	@GetMapping("/run")
	public String run(@RequestParam String cmd) throws Exception {
	    Runtime.getRuntime().exec(cmd); // crítico
	}
	
	@GetMapping("/no-test")
	public String noTestMethod() {
		int unused = 0;
		String text = "hello";

	    return "no test";
	}

	public void hugeMethod() {
		// TODO: pendiente
		// FIXME: reparar
		// código muerto
		// int x = 10;

		
		
	    for(int i=0; i<100; i++){
	        System.out.println(i);
	    }
	    // copia el loop varias veces
	}

	
	public int complex(int x){
	    if(x==1) return 1;
	    if(x==2) return 2;
	    return 0;
	}

	
	public int fail(int x){
	    return x / (x - x);  // posible división por cero
	}

	
	public String npe(String s){
	    return s.toString();
	}

	public void arrayBug() {
	    int[] a = new int[2];
	    int x = a[5]; // index out of bounds
	}

	if(name == "test") { ... }

}
