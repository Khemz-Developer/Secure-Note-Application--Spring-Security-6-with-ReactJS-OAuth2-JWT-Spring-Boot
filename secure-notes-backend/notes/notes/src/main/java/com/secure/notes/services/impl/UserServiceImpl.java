package com.secure.notes.services.impl;

import com.secure.notes.dtos.UserDTO;
import com.secure.notes.models.AppRole;
import com.secure.notes.models.PasswordResetToken;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.repositories.PasswordResetTokenRepository;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.repositories.UserRepository;
import com.secure.notes.services.TotpService;
import com.secure.notes.services.UserService;
import com.secure.notes.util.EmailService;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.Date;
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    PasswordEncoder passwordEncoder;
    
    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    EmailService emailService;

    @Autowired
    TotpService totpService;

    @Value("${frontend.url}")
    String frontendUrl;

    @Override
    public void updateUserRole(Long userId, String roleName) {
        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        AppRole appRole = AppRole.valueOf(roleName);
        Role role = roleRepository.findByRoleName(appRole)
                .orElseThrow(() -> new RuntimeException("Role not found"));
        user.setRole(role);
        userRepository.save(user);
    }


    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }


    @Override
    public UserDTO getUserById(Long id) {
//        return userRepository.findById(id).orElseThrow();
        User user = userRepository.findById(id).orElseThrow();
        return convertToDto(user);
    }

    private UserDTO convertToDto(User user) {
        return new UserDTO(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.getTwoFactorSecret(),
                user.isTwoFactorEnabled(),
                user.getSignUpMethod(),
                user.getRole(),
                user.getCreatedDate(),
                user.getUpdatedDate()
        );
    }

    // UserServiceImpl.java
    @Override
    public User findByUsername(String username) {
        Optional<User> user = userRepository.findByUserName(username);
        return user.orElseThrow(() -> new RuntimeException("User not found with username: " + username));
    }

    @Override
    public void updateAccountLockStatus(Long userId, boolean lock) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setAccountNonLocked(!lock);

        // Reset failed attempts if we're unlocking the account
        if (!lock) {
            user.setFailedAttempts(0);
            user.setLockTime(null);
        } else if (lock && user.getLockTime() == null) {
            // Set lock time if we're locking the account and it doesn't have a lock time yet
            user.setLockTime(new Date());
        }

        userRepository.save(user);
    }

    @Override
    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    @Override
    public void updateAccountExpiryStatus(Long userId, boolean expire) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setAccountNonExpired(!expire);
        userRepository.save(user);
    }

    @Override
    public void updatePassword(Long userId, String password) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            user.setPassword(passwordEncoder.encode(password));
            user.setCredentialsNonExpired(true);
            user.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            userRepository.save(user);
        } catch (Exception e) {
            throw new RuntimeException("Failed to update password");
        }
    }


    @Override
    public void updateCredentialsExpiryStatus(Long userId, boolean expire) {
        // Find the user by ID or throw an exception if the user is not found
        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));

        // If we want to expire the credentials
        if (expire) {
            user.setCredentialsNonExpired(false); // Mark credentials as expired
            user.setCredentialsExpiryDate(LocalDate.now().minusDays(1)); // Set the expiry date to today
        } else {
            user.setCredentialsNonExpired(true); // Mark credentials as non-expired
            user.setCredentialsExpiryDate(LocalDate.now().plusYears(1)); // Set the expiry date to one year from now
        }

        // Save the updated user entity to the database
        userRepository.save(user);
    }


    @Override
    public void updateAccountEnabledStatus(Long userId, boolean enabled) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setEnabled(enabled);
        userRepository.save(user);
    }

    @Override
    public void generatePasswordResetToken(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

        String token = UUID.randomUUID().toString();
        Instant expiryDate = Instant.now().plusMillis(86400000); // 24 hours

        PasswordResetToken passwordResetToken = new PasswordResetToken(token, expiryDate, user);
        passwordResetToken.setUsed(false);
        passwordResetTokenRepository.save(passwordResetToken);

        String resetUrl = frontendUrl + "/reset-password?token=" + token;
        // send email with resetUrl
        emailService.sendPasswordResetEmail(user.getEmail(), resetUrl);

    }

    @Override
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken passwordResetToken = passwordResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (passwordResetToken.isUsed()) {
            throw new RuntimeException("Token already used");
        }

        if (passwordResetToken.getExpiryDate().isBefore(Instant.now())) {
            throw new RuntimeException("Token expired");
        }

        User user = passwordResetToken.getUser();
        System.out.println(newPassword);
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setCredentialsNonExpired(true);
        user.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
        userRepository.save(user);

        passwordResetToken.setUsed(true);
        passwordResetTokenRepository.save(passwordResetToken);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        Optional<User> user = userRepository.findByEmail(email);
        return user;
    }

    @Override
    public void registerUser(User user) {

       if(user.getPassword() != null) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        userRepository.save(user);
    }

    @Override
    public void updateUser(User user) {
        userRepository.save(user);
    }

    @Override
    public GoogleAuthenticatorKey generate2FASecret(Long userId){ // generate secret key For 2FA for user

        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        GoogleAuthenticatorKey key = totpService.generateSecretKey();
        user.setTwoFactorSecret(key.getKey());
        userRepository.save(user);
        return key;

    }

    @Override
    public boolean validate2FACode(Long userId, int code){ // validate 2FA code means verify the code entered by user, if verified return true else false

        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        return totpService.verifyCode(user.getTwoFactorSecret(), code);
    }

    @Override
    public void enable2FA(Long userId){
        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        user.setTwoFactorEnabled(true);
        userRepository.save(user);

    }

    @Override
    public void disable2FA(Long userId){
        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        user.setTwoFactorEnabled(false);
        userRepository.save(user);
    }

}
