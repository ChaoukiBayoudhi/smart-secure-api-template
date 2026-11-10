package com.example.smartsecure.controller;

import com.example.smartsecure.domain.AppUser;
import com.example.smartsecure.domain.Role;
import com.example.smartsecure.dto.LoginRequest;
import com.example.smartsecure.dto.TokenResponse;
import com.example.smartsecure.repository.UserRepository;
import com.example.smartsecure.security.JwtTokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Set;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        AppUser user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

        if (user.isAccountLocked()) {
            throw new ResponseStatusException(HttpStatus.LOCKED, "Account is locked due to security policy");
        }

        if (!passwordEncoder.matches(request.secretPhrase(), user.getEncodedCredential())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        Set<Role> roles = user.getRoles().isEmpty() ? Set.of(Role.ROLE_USER) : user.getRoles();
        String token = jwtTokenService.generateAccessToken(user.getUsername(), roles);

        return ResponseEntity.ok(new TokenResponse(
                token,
                "Bearer",
                jwtTokenService.getAccessTokenTtlSeconds()
        ));
    }
}
