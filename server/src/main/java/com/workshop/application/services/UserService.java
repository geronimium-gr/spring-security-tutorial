package com.workshop.application.services;

import com.workshop.application.models.User;
import org.springframework.http.ResponseEntity;

import java.util.Optional;

public interface UserService {

    /*
     * For creating new user
     * */
    void createUser(User user);

    /*
     * For getting all users
     * */
    Iterable<User> getUsers();

    /*
     * For deleting user
     * */
    ResponseEntity<Object> deleteUser(Long id);

    /*
     * For updating user
     * */
    ResponseEntity<Object> updateUser(Long id, User user);

    /*
     * For finding a user by the username
     * */
    Optional<User> findUserByEmail(String email);
}

