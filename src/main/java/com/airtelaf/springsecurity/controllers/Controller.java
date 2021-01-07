package com.airtelaf.springsecurity.controllers;

import com.airtelaf.springsecurity.models.AuthenticationRequest;
import com.airtelaf.springsecurity.services.MyUserDetailsService;
import com.airtelaf.springsecurity.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class Controller {


    private final AuthenticationManager authenticationManager;


    private final MyUserDetailsService myUserDetailsService;

    private final JwtUtil jwtUtil;

    @GetMapping("/hello")
    public String hello(){
        return "Hello world";
    }

    @GetMapping("/welcome")
    public String welcome(){
        return "welcome world";
    }

    @PostMapping("/authenticate")
    public String createAuthenticatedUser(@RequestBody AuthenticationRequest authenticationRequest){
        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        }
        catch (BadCredentialsException e){
            e.printStackTrace();
            throw e;
        }

        return jwtUtil.generateToken(myUserDetailsService.loadUserByUsername(authenticationRequest.getUsername()));
    }
}
