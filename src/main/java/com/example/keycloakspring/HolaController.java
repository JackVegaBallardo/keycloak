package com.example.keycloakspring;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HolaController {

  @GetMapping("/public/hello")
  public String publico() {
    return "Hola público";
  }

  @GetMapping("/secure/hello")
  public String seguro() {
    return "Hola seguro  (token válido ok)";
  }
}