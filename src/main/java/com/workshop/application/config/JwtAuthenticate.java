package com.workshop.application.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;

public class JwtAuthenticate implements AuthenticationEntryPoint, Serializable {
    // serialVersionUID serves as the "state" of a serializable object. This is used by Java in deserializing a
    // serialized object.
    //serialization is the process of transmitting information in a different data structure (ie. an object is
    // serialized into a string to be transmitted and gets deserialized back into an object when it reaches its
    // destination
    @Serial
    private static final long serialVersionUID = -7858869558953243875L;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         // AuthenticationException is a class in Spring Security that contains all exceptions related to an Authentication object being invalid
                         AuthenticationException authException) throws IOException {

        /*
        * Avoid using user-friendly errors in the server used sendError to catch errors.
        * */
//        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getOutputStream().println("{ \"error\": \"" + HttpStatus.UNAUTHORIZED.getReasonPhrase() + "\" }");

        /*
        * CAME FROM BasicAuthenticationEntryPoint to handle HttpStatus
        * */
//        response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());


    }
}
