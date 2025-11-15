package com.github_actions.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(Controller.class)
class ControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void testMensajeEndpoint() throws Exception {
		mockMvc.perform(get("/")).andExpect(status().isOk()).andExpect(content().string("Prueba controller"));
		assertTrue(true);
	}
	
	@Test
	void testMensajeEndpointFailed() throws Exception {
		mockMvc.perform(get("/")).andExpect(status().isOk()).andExpect(content().string("Prueba controller"));
		assertTrue(false);
	}
}