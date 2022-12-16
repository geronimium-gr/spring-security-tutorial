package com.workshop.application.repositories;

import com.workshop.application.models.User;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<User, Object> {

    User findUserByEmail(String email);

    @Query(value = "SELECT * FROM users WHERE email = ?1 LIMIT 1", nativeQuery = true)
    User findEmailIfExists(String email);
}
