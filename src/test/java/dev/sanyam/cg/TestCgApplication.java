package dev.sanyam.cg;

import org.springframework.boot.SpringApplication;

public class TestCgApplication {

	public static void main(String[] args) {
		SpringApplication.from(CgApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
