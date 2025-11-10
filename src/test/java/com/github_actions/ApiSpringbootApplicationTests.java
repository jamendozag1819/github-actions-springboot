package com.github_actions;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class ApiSpringbootApplicationTests {
 
	@Test
	void mainMethodRuns() {
		ApiSpringbootApplication.main(new String[] {});
		assertTrue(true);
	}

}
