package com.sbs.apple;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@EnableJpaAuditing
@SpringBootApplication
public class AppleApplication {
	public static void main(String[] args) {
		SpringApplication.run(AppleApplication.class, args);
	}

}
