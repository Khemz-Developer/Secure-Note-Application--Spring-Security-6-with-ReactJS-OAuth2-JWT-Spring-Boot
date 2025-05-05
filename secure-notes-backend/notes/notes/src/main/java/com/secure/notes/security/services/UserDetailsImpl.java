package com.secure.notes.security.services;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

import com.secure.notes.models.User;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

@NoArgsConstructor
@Data
public class UserDetailsImpl implements UserDetails {
    private static final long serialVersionUID = 1L;

    private Long id;
    private String username;
    private String email;


    @JsonIgnore
    private String password;

    private boolean is2faEnabled;
    private boolean isAccountLocked;
    private boolean isCredentialsExpired;
    private boolean isEnabled;


    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(Long id, String username, String email, String password,
                           boolean is2faEnabled, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.is2faEnabled = is2faEnabled;
        this.authorities = authorities;

    }

    public UserDetailsImpl(Long id, String username, String email, String password,
                           boolean is2faEnabled, boolean isAccountLocked, boolean isCredentialsExpired,
                           boolean isEnabled, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.is2faEnabled = is2faEnabled;
        this.isAccountLocked = isAccountLocked;
        this.isCredentialsExpired = isCredentialsExpired;
        this.isEnabled = isEnabled;
        this.authorities = authorities;
    }

    public static UserDetailsImpl build(User user) {
        GrantedAuthority authority = new SimpleGrantedAuthority(user.getRole().getRoleName().name());

        return new UserDetailsImpl(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.getPassword(),
                user.isTwoFactorEnabled(),
                user.isAccountLocked(), // Add check for account lock status
                user.isCredentialsExpired(), // Add check for credentials expired status
                user.isEnabled(), // Check if account is disabled
                List.of(authority) // Wrapping the single authority in a list
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return !isCredentialsExpired; // Returns false if credentials are expired
    }

    @Override
    public boolean isAccountNonLocked() {
        return !isAccountLocked; // Returns false if account is locked
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !isCredentialsExpired; // Returns false if credentials are expired
    }

    @Override
    public boolean isEnabled() {
        return isEnabled; // Returns false if account is disabled
    }

    public boolean is2faEnabled() {
        return is2faEnabled;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        UserDetailsImpl user = (UserDetailsImpl) o;
        return Objects.equals(id, user.id);
    }
}