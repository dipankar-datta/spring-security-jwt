package com.dipankar.springsecurityjwt.models;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor @Getter
public class AuthenticationResponse {

    private final String jwtToken;
}
