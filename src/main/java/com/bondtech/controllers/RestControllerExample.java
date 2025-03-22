package com.bondtech.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;


@RestController
public class RestControllerExample {

    @Autowired
    private WebClient webClient;

    @GetMapping("/to_get_strings")
    public String getStrings() {
        return webClient.get().uri("http://localhost:60002/strings").attributes(clientRegistrationId("custom-client")).retrieve().bodyToMono(String.class).block();
    }
}
