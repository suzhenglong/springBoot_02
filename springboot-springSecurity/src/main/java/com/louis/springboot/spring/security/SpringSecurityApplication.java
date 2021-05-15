package com.louis.springboot.spring.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

/**
 * 启动器
 * @author Louis
 * @date Nov 28, 2018
 */
@SpringBootApplication
public class SpringSecurityApplication {

	//http://localhost:8080/swagger-ui.html
	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}
}
