package com.secure.notes.services.impl;

import com.secure.notes.models.User;
import com.secure.notes.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

@Service
public class LoginAttemptService {
    
    public static final int MAX_FAILED_ATTEMPTS = 3;
    
    @Autowired
    private UserRepository userRepository;
    
    public void incrementFailedAttempts(String username) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        
        user.setFailedAttempts(user.getFailedAttempts() + 1);
        
        // Lock the account if attempts reach the limit
        if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.setAccountNonLocked(false);
            user.setLockTime(new Date());
        }
        
        userRepository.save(user);
    }
    
    public void resetFailedAttempts(String username) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        
        user.setFailedAttempts(0);
        userRepository.save(user);
    }
    
    // Optional: Method to unlock accounts automatically after a certain period
    @Scheduled(fixedRate = 3600000) // Run every hour
    public void unlockAccounts() {
        // Get all locked accounts
        List<User> lockedUsers = userRepository.findByAccountNonLockedFalse();
        
        // Set a specific time frame, e.g., 24 hours
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, -24);
        Date unlockTime = calendar.getTime();
        
        for (User user : lockedUsers) {
            if (user.getLockTime().before(unlockTime)) {
                user.setAccountNonLocked(true);
                user.setFailedAttempts(0);
                user.setLockTime(null);
                userRepository.save(user);
            }
        }
    }
}