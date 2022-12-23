package com.workshop.application.controllers;

import com.workshop.application.config.JwtToken;
import com.workshop.application.dao.UserDao;
import com.workshop.application.dto.AuthRequest;
import com.workshop.application.models.User;
import com.workshop.application.repositories.UserRepository;
import com.workshop.application.services.JwtUserDetailsService;
import com.workshop.application.services.UserService;
import lombok.RequiredArgsConstructor;
import org.hibernate.PropertyValueException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;

    private final JwtUserDetailsService userDetailsService;

    private final JwtToken jwtToken;

    private final UserRepository userRepository;

    private final UserService userService;

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

    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody Map<String, String> body){

        String message;
        HttpStatus httpStatus;


        try{
            String firstName = body.get("firstName");
            String lastName = body.get("lastName");
            String email = body.get("email");

            if (userService.findUserByEmail(email).isPresent()){
                return new ResponseEntity<>("Email already exists", HttpStatus.BAD_REQUEST);
            }

            /*
             * Create a new instance of User
             * */
            String encryptPassword = new BCryptPasswordEncoder().encode(body.get("password"));

            User newUser = new User(firstName, lastName, email, encryptPassword);

            userService.createUser(newUser);

            message = "User registered successfully";
            httpStatus = HttpStatus.CREATED;
        } catch (DataIntegrityViolationException e) {
            message = "Fields must not be empty";
            httpStatus = HttpStatus.BAD_REQUEST;
        } catch (Exception e) {
            message = "Error occurred: " + e.getClass().getSimpleName();
            httpStatus = HttpStatus.BAD_REQUEST;
        }


        return new ResponseEntity<>(message, httpStatus);

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
