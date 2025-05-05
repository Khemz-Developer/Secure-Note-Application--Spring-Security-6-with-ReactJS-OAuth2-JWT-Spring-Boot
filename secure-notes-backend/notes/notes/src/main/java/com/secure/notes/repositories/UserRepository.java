package com.secure.notes.repositories;

import com.secure.notes.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUserName(String username);

    boolean existsByUserName(String username);

    boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);

    List<User> findByAccountNonLockedFalse();


}
