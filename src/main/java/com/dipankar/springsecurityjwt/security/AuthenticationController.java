package com.dipankar.springsecurityjwt.security;

import com.dipankar.springsecurityjwt.models.AuthenticationRequest;
import com.dipankar.springsecurityjwt.models.AuthenticationResponse;
import com.dipankar.springsecurityjwt.services.UserLoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserLoginService userLoginService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> generateAuthenticationToken(
            @RequestBody AuthenticationRequest authenticationRequest) throws Exception {


       try {
           authenticationManager
                   .authenticate(
                           new UsernamePasswordAuthenticationToken(
                                   authenticationRequest.getUsername(),
                                   authenticationRequest.getPassword()));
       } catch (BadCredentialsException e) {
           throw new Exception("Invalid username or password");
       }

       final UserDetails userDetails = userLoginService.loadUserByUsername(authenticationRequest.getUsername());

       final String token = jwtUtil.generateToken(userDetails);

       return ResponseEntity.ok(new AuthenticationResponse(token));
    }
}
