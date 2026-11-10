package com.example.smartsecure.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 64, message = "Username must be between 3 and 64 characters")
        @Pattern(regexp = "^[a-zA-Z0-9._-]+$", message = "Username contains invalid characters")
        String username,

        @NotBlank(message = "Secret phrase is required")
        @Size(min = 8, max = 128, message = "Secret phrase must be between 8 and 128 characters")
        String secretPhrase
) {
}
