package com.workshop.application.services;

import com.workshop.application.models.User;
import com.workshop.application.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public void createUser(User user) {
        userRepository.save(user);
    }

    @Override
    public Iterable<User> getUsers() {
        return null;
    }

    @Override
    public ResponseEntity<Object> deleteUser(Long id) {
        return null;
    }

    @Override
    public ResponseEntity<Object> updateUser(Long id, User user) {
        return null;
    }

    @Override
    public Optional<User> findUserByEmail(String email) {

        return Optional.ofNullable(userRepository.findUserByEmail(email));
    }
}
