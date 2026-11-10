package com.example.smartsecure.dto;

public record TokenResponse(
        String accessToken,
        String tokenType,
        long expiresInSeconds
) {
}
