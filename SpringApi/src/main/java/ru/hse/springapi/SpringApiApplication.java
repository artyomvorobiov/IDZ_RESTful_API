package ru.hse.springapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RestController;


@RestController
@SpringBootApplication
public class SpringApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringApiApplication.class, args);
    }




}
