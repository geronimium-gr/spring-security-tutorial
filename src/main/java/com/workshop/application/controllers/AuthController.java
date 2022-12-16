package com.workshop.application.controllers;

import com.workshop.application.config.JwtToken;
import com.workshop.application.dao.UserDao;
import com.workshop.application.dto.AuthRequest;
import com.workshop.application.models.User;
import com.workshop.application.repositories.UserRepository;
import com.workshop.application.services.JwtUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;

    private final JwtUserDetailsService userDetailsService;

    private final JwtToken jwtToken;

    private final UserRepository userRepository;

    @PostMapping("/login")
    public ResponseEntity<Object> authenticate(@RequestBody AuthRequest request) throws Exception {

        HashMap<String, String> response = new HashMap<>();

        authenticate(request.getEmail(), request.getPassword());

        final UserDetails USER = userDetailsService.loadUserByUsername(request.getEmail());

        final String TOKEN = jwtToken.generateToken(USER);

        if (USER != null) {
            response.put("status", "success");
            response.put("user", USER.getUsername());
            response.put("token", TOKEN);
            return new ResponseEntity<>(response, HttpStatus.OK);
        }

        return new ResponseEntity<>("Some error occurred", HttpStatus.BAD_REQUEST);
    }

    private void authenticate(String email, String password) throws Exception {
        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        } catch (DisabledException e){
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e){
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }

}
