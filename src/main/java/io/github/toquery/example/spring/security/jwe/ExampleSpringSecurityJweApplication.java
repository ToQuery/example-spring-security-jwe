package io.github.toquery.example.spring.security.jwe;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(value = {JweProperties.class})
public class ExampleSpringSecurityJweApplication {

	public static void main(String[] args) {
		SpringApplication.run(ExampleSpringSecurityJweApplication.class, args);
	}

}
