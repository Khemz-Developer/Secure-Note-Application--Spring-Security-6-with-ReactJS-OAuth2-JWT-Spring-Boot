package com.secure.notes.services;

import com.secure.notes.dtos.UserDTO;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

import java.util.List;
import java.util.Optional;

public interface UserService {


    void updateUserRole(Long userId, String roleName);

    List<User> getAllUsers();

    UserDTO getUserById(Long id);


    // UserServiceImpl.java
    User findByUsername(String username);

    void updateAccountLockStatus(Long userId, boolean lock);

    List<Role> getAllRoles();

    void updateAccountExpiryStatus(Long userId, boolean expire);

    void updatePassword(Long userId, String password);

    void updateAccountEnabledStatus(Long userId, boolean enabled);

    void updateCredentialsExpiryStatus(Long userId, boolean expire);

    void generatePasswordResetToken(String email);

    void resetPassword(String token, String password);

    Optional<User> findByEmail(String email);

    void registerUser(User newUser);

    void updateUser(User user);

    GoogleAuthenticatorKey generate2FASecret(Long userId);

    boolean validate2FACode(Long userId, int code);

    void enable2FA(Long userId);

    void disable2FA(Long userId);
}
