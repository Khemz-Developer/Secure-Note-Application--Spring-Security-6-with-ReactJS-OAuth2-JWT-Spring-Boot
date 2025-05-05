package com.secure.notes.controllers;


import com.secure.notes.models.AppRole;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.repositories.UserRepository;
import com.secure.notes.security.jwt.JwtUtils;
import com.secure.notes.security.request.LoginRequest;
import com.secure.notes.security.request.SignupRequest;
import com.secure.notes.security.response.LoginResponse;
import com.secure.notes.security.response.MessageResponse;
import com.secure.notes.security.response.UserInfoResponse;
import com.secure.notes.security.services.UserDetailsImpl;
import com.secure.notes.services.TotpService;
import com.secure.notes.services.UserService;
import com.secure.notes.services.impl.LoginAttemptService;
import com.secure.notes.util.AuthUtil;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;



@RestController
@RequestMapping("/api/auth")
//@CrossOrigin(origins = "http://localhost:3000", maxAge = 3600, allowCredentials="true")
public class AuthController {

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    UserService userService;

    @Autowired
    AuthUtil authUtil;

    @Autowired
    TotpService totpService;

    @Autowired
    LoginAttemptService loginAttemptService;


//    @PostMapping("/public/signin")
//    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
//        Authentication authentication;
//        try {
//            authentication = authenticationManager
//                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
//        } catch (AuthenticationException exception) {
//            Map<String, Object> map = new HashMap<>();
//            map.put("message", "Bad credentials");
//            map.put("status", false);
//            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
//        }
//
//        //set the authentication
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
//
//        System.out.println("userDetails.isAccountNonLocked():" + userDetails);
//        // Handle account lock, disabled, and expired credentials
//        if (!userDetails.isAccountNonLocked()) {
//            Map<String, Object> map = new HashMap<>();
//            map.put("message", "Account is locked");
//            map.put("status", false);
//            return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);
//        }
//
//        if (!userDetails.isEnabled()) {
//            Map<String, Object> map = new HashMap<>();
//            map.put("message", "Account is disabled");
//            map.put("status", false);
//            return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);
//        }
//
//        if (!userDetails.isCredentialsNonExpired()) {
//            Map<String, Object> map = new HashMap<>();
//            map.put("message", "Credentials expired");
//            map.put("status", false);
//            return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);
//        }
//
//        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);
//
//        // Collect roles from the UserDetails
//        List<String> roles = userDetails.getAuthorities().stream()
//                .map(item -> item.getAuthority())
//                .collect(Collectors.toList());
//
//        // Prepare the response body, now including the JWT token directly in the body
//        LoginResponse response = new LoginResponse(userDetails.getUsername(), roles, jwtToken);
//
//        // Return the response entity with the JWT token included in the response body
//        return ResponseEntity.ok(response);
//    };

//    @PostMapping("/public/signin")
//    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
//        try {
//            // Attempt authentication
//            Authentication authentication = authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(
//                            loginRequest.getUsername(),
//                            loginRequest.getPassword()
//                    )
//            );
//
//            // Set the authentication in SecurityContext
//            SecurityContextHolder.getContext().setAuthentication(authentication);
//
//            // Extract user details
//            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
//
//            // Generate JWT token
//            String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);
//
//            // Collect roles
//            List<String> roles = userDetails.getAuthorities().stream()
//                    .map(item -> item.getAuthority())
//                    .collect(Collectors.toList());
//
//            // Create and return response with JWT token
//            LoginResponse response = new LoginResponse(
//                    userDetails.getUsername(),
//                    roles,
//                    jwtToken
//            );
//
//            return ResponseEntity.ok(response);
//
//        } catch (LockedException e) {
//            // Handle locked account
//            Map<String, Object> map = new HashMap<>();
//            map.put("message", "Account is locked");
//            map.put("status", false);
//            return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);
//
//        } catch (DisabledException e) {
//            // Handle disabled account
//            Map<String, Object> map = new HashMap<>();
//            map.put("message", "Account is disabled");
//            map.put("status", false);
//            return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);
//
//        } catch (CredentialsExpiredException e) {
//            // Handle expired credentials
//            Map<String, Object> map = new HashMap<>();
//            map.put("message", "Credentials expired");
//            map.put("status", false);
//            return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);
//
//        } catch (BadCredentialsException e) {
//
//            // Increment failed attempts on bad credentials
//            loginAttemptService.incrementFailedAttempts(loginRequest.getUsername());
//
//            // Check if account should be locked after this attempt
//            User user = userRepository.findByUserName(loginRequest.getUsername())
//                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
//
//            if (!user.isAccountNonLocked()) {
//                Map<String, Object> map = new HashMap<>();
//                map.put("message", "Account has been locked due to 3 failed attempts");
//                map.put("status", false);
//                return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);
//            } else {
//                // Return normal bad credentials response
//                Map<String, Object> map = new HashMap<>();
//                int attemptsLeft = LoginAttemptService.MAX_FAILED_ATTEMPTS - user.getFailedAttempts();
//                map.put("message", "Bad credentials. Attempts left: " + attemptsLeft);
//                map.put("status", false);
//                return new ResponseEntity<>(map, HttpStatus.UNAUTHORIZED);
//            }
//
//        } catch (AuthenticationException e) {
//            // Handle any other authentication exceptions
//            Map<String, Object> map = new HashMap<>();
//            map.put("message", "Authentication failed: " + e.getMessage());
//            map.put("status", false);
//            return new ResponseEntity<>(map, HttpStatus.UNAUTHORIZED);
//        }
//    }

    @PostMapping("/public/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        try {
            // First check if the user exists and if credentials are expired
            User user = userRepository.findByUserName(loginRequest.getUsername())
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            // Check if credentials are expired before attempting authentication
            if (!user.isCredentialsNonExpired()) {
                Map<String, Object> map = new HashMap<>();
                map.put("message", "Credentials expired. Please change your password.");
                map.put("status", false);
                return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);
            }

            // Attempt authentication only if credentials are not expired
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            // Set the authentication in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Extract user details
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            // Generate JWT token
            String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

            // Collect roles
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            // Reset failed attempts on successful login
            loginAttemptService.resetFailedAttempts(loginRequest.getUsername());

            // Create and return response with JWT token
            LoginResponse response = new LoginResponse(
                    userDetails.getUsername(),
                    roles,
                    jwtToken
            );

            return ResponseEntity.ok(response);

        } catch (LockedException e) {
            // Handle locked account
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Account is locked");
            map.put("status", false);
            return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);

        } catch (DisabledException e) {
            // Handle disabled account
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Account is disabled");
            map.put("status", false);
            return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);

        } catch (CredentialsExpiredException e) {
            // This is a fallback in case the credential check is bypassed somehow
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Credentials expired");
            map.put("status", false);
            return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);

        } catch (BadCredentialsException e) {
            // Increment failed attempts on bad credentials
            loginAttemptService.incrementFailedAttempts(loginRequest.getUsername());

            try {
                // Check if account should be locked after this attempt
                User user = userRepository.findByUserName(loginRequest.getUsername())
                        .orElseThrow(() -> new UsernameNotFoundException("User not found"));

                if (!user.isAccountNonLocked()) {
                    Map<String, Object> map = new HashMap<>();
                    map.put("message", "Account has been locked due to 3 failed attempts");
                    map.put("status", false);
                    return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);
                } else {
                    // Return normal bad credentials response
                    Map<String, Object> map = new HashMap<>();
                    int attemptsLeft = LoginAttemptService.MAX_FAILED_ATTEMPTS - user.getFailedAttempts();
                    map.put("message", "Bad credentials. Attempts left: " + attemptsLeft);
                    map.put("status", false);
                    return new ResponseEntity<>(map, HttpStatus.UNAUTHORIZED);
                }
            } catch (UsernameNotFoundException unfe) {
                // User not found but don't reveal this information
                Map<String, Object> map = new HashMap<>();
                map.put("message", "Bad credentials");
                map.put("status", false);
                return new ResponseEntity<>(map, HttpStatus.UNAUTHORIZED);
            }

        } catch (AuthenticationException e) {
            // Handle any other authentication exceptions
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Authentication failed: " + e.getMessage());
            map.put("status", false);
            return new ResponseEntity<>(map, HttpStatus.UNAUTHORIZED);
        }
    }


    @PostMapping("/public/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUserName(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Role role;

        if (strRoles == null || strRoles.isEmpty()) {
            role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        } else {
            String roleStr = strRoles.iterator().next();
            if (roleStr.equals("admin")) {
                role = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            } else {
                role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            }

            user.setAccountNonLocked(true);
            user.setAccountNonExpired(true);
            user.setCredentialsNonExpired(true);
            user.setEnabled(true);
            user.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            user.setAccountExpiryDate(LocalDate.now().plusYears(1));
            user.setTwoFactorEnabled(false);
            user.setSignUpMethod("email");
        }
        user.setRole(role);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @GetMapping("/user")
    public ResponseEntity<?> getUserDetails(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userService.findByUsername(userDetails.getUsername());

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        UserInfoResponse response = new UserInfoResponse(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.isTwoFactorEnabled(),
                roles
        );

        return ResponseEntity.ok().body(response);
    }

    @GetMapping("/username")
    public String currentUsername(@AuthenticationPrincipal UserDetails userDetails) {
        return (userDetails != null) ? userDetails.getUsername() : "" ;
    }

    @PostMapping("/public/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {

        try{
            userService.generatePasswordResetToken(email);
            return ResponseEntity.ok().body(new MessageResponse("Password reset token generated successfully!"));
        }catch (Exception e){
            e.printStackTrace();
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email not found!"));
        }

    }

    @PostMapping("/public/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestParam String newPassword) {
        try{
            userService.resetPassword(token, newPassword);
            return ResponseEntity.ok().body(new MessageResponse("Password reset successfully!"));
        }catch (Exception e){
            e.printStackTrace();
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Password reset failed!"));
        }
    }

    //======== 2FA AUTHENTICATION =========
    @PostMapping("/enable-2fa")
    public ResponseEntity<String> enable2FA(){
        Long userId = authUtil.loggedInUserId();
        GoogleAuthenticatorKey secret = userService.generate2FASecret(userId);
        String qrCodeUrl = totpService.getQrCodeUrl(secret, userService.getUserById(userId).getUserName());

        return ResponseEntity.ok().body(qrCodeUrl);
    }

    @PostMapping("/disable-2fa")
    public ResponseEntity<String> disable2FA(){
        Long userId = authUtil.loggedInUserId();
        userService.disable2FA(userId);
        return ResponseEntity.ok().body("2FA disabled successfully!");
    }


    @PostMapping("/verify-2fa")
    public ResponseEntity<String> verify2FA(@RequestParam int code){
        Long userId = authUtil.loggedInUserId();
        boolean isValid = userService.validate2FACode(userId, code);
        if(isValid){
            userService.enable2FA(userId);
            return ResponseEntity.ok().body("2FA code is valid!");
        }else {
            //return ResponseEntity.badRequest().body("2FA code is invalid!");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("2FA code is invalid!");
        }
    }

    @GetMapping("/user/2fa-status")
    public ResponseEntity<?> get2FAStatus(){
        User user = authUtil.loggedInUser();
        if(user != null){
            return ResponseEntity.ok().body(Map.of("2faEnabled", user.isTwoFactorEnabled()));
        }else {
            return ResponseEntity.badRequest().body(new MessageResponse("User not found!"));
        }
    }

    @PostMapping("/public/verify-2fa-login")
    public ResponseEntity<?> verify2FALogin(@RequestParam int code, @RequestParam String jwtToken){
        String username = jwtUtils.getUserNameFromJwtToken(jwtToken);
        User user = userService.findByUsername(username);
        boolean isValid = userService.validate2FACode(user.getUserId(), code);
        if(isValid){

            return ResponseEntity.ok().body(new MessageResponse("2FA code is valid!"));

        }else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("2FA code is invalid!");
        }
    }



}
