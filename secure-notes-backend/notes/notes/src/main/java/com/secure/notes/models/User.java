//package com.secure.notes.models;
//
//import com.fasterxml.jackson.annotation.JsonBackReference;
//import com.fasterxml.jackson.annotation.JsonIgnore;
//import jakarta.persistence.*;
//import jakarta.validation.constraints.Email;
//import jakarta.validation.constraints.NotBlank;
//import jakarta.validation.constraints.Size;
//import lombok.Data;
//import lombok.NoArgsConstructor;
//import lombok.ToString;
//import org.hibernate.annotations.CreationTimestamp;
//import org.hibernate.annotations.UpdateTimestamp;
//
//import java.time.LocalDate;
//import java.time.LocalDateTime;
//
//@Entity
//@Data
//@NoArgsConstructor
//@Table(name = "users",
//        uniqueConstraints = {
//                @UniqueConstraint(columnNames = "username"),
//                @UniqueConstraint(columnNames = "email")
//        })
//public class User{
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    @Column(name = "user_id")
//    private Long userId;
//
//    @NotBlank
//    @Size(max = 20)
//    @Column(name = "username")
//    private String userName;
//
//    @NotBlank
//    @Size(max = 50)
//    @Email
//    @Column(name = "email")
//    private String email;
//
//    @Size(max = 120)
//    @Column(name = "password")
//    @JsonIgnore
//    private String password;
//
//    private boolean accountNonLocked = true;
//    private boolean accountNonExpired = true;
//    private boolean credentialsNonExpired = true;
//    private boolean enabled = true;
//
//    private LocalDate credentialsExpiryDate;
//    private LocalDate accountExpiryDate;
//
//    private String twoFactorSecret;
//    private boolean isTwoFactorEnabled = false;
//    private String signUpMethod;
//
//    @ManyToOne(fetch = FetchType.EAGER, cascade = {CascadeType.MERGE})
//    @JoinColumn(name = "role_id", referencedColumnName = "role_id")
//    @JsonBackReference
//    @ToString.Exclude
//    private Role role;
//
//    @CreationTimestamp
//    @Column(updatable = false)
//    private LocalDateTime createdDate;
//
//    @UpdateTimestamp
//    private LocalDateTime updatedDate;
//
//    public User(String userName, String email, String password) {
//        this.userName = userName;
//        this.email = email;
//        this.password = password;
//    }
//
//    public User(String userName, String email) {
//        this.userName = userName;
//        this.email = email;
//    }
//
//    @Override
//    public boolean equals(Object o) {
//        if (this == o) return true;
//        if (!(o instanceof User)) return false;
//        return userId != null && userId.equals(((User) o).getUserId());
//    }
//
//    @Override
//    public int hashCode() {
//        return getClass().hashCode();
//    }
//}
package com.secure.notes.models;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Date;

@Entity
@Data
@NoArgsConstructor
@Table(name = "users",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "username"),
                @UniqueConstraint(columnNames = "email")
        })
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;

    @NotBlank
    @Size(max = 20)
    @Column(name = "username")
    private String userName;

    @NotBlank
    @Size(max = 50)
    @Email
    @Column(name = "email")
    private String email;

    @Size(max = 120)
    @Column(name = "password")
    @JsonIgnore
    private String password;

    private boolean accountNonLocked = true; // Track if account is locked
    private boolean accountNonExpired = true; // Track if account is expired
    private boolean credentialsNonExpired = true; // Track if credentials are expired
    private boolean enabled = true; // Track if account is enabled

    private LocalDate credentialsExpiryDate; // Track credentials expiry
    private LocalDate accountExpiryDate; // Track account expiry

    private String twoFactorSecret;
    private boolean isTwoFactorEnabled = false;
    private String signUpMethod;

    @ManyToOne(fetch = FetchType.EAGER, cascade = {CascadeType.MERGE})
    @JoinColumn(name = "role_id", referencedColumnName = "role_id")
    @JsonBackReference
    @ToString.Exclude
    private Role role;

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdDate;

    @UpdateTimestamp
    private LocalDateTime updatedDate;

    private int failedAttempts = 0; // Track failed login attempts
    private Date lockTime; // Track lock time

    // Constructor for username, email, and password
    public User(String userName, String email, String password) {
        this.userName = userName;
        this.email = email;
        this.password = password;
    }

    // Constructor for username and email (for signup)
    public User(String userName, String email) {
        this.userName = userName;
        this.email = email;
    }

    // Account lock check
    public boolean isAccountLocked() {
        return !accountNonLocked; // If accountNonLocked is false, account is locked
    }

    // Account expiration check
    public boolean isAccountExpired() {
        return accountExpiryDate != null && accountExpiryDate.isBefore(LocalDate.now());
    }

    // Credentials expiration check


    public boolean isCredentialsExpired() {

        // Otherwise check the date
        return credentialsExpiryDate != null && credentialsExpiryDate.isBefore(LocalDate.now());
    }





    public int getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public Date getLockTime() {
        return lockTime;
    }

    public void setLockTime(Date lockTime) {
        this.lockTime = lockTime;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User)) return false;
        return userId != null && userId.equals(((User) o).getUserId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }




}
