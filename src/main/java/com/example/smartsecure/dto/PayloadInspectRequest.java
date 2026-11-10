package com.example.smartsecure.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PayloadInspectRequest(
        @NotBlank(message = "HTTP method is required")
        @Size(max = 16)
        String httpMethod,

        @NotBlank(message = "Request path is required")
        @Size(max = 255)
        String requestPath,

        @NotBlank(message = "Client IP is required")
        @Size(max = 64)
        String clientIp,

        @NotBlank(message = "Payload body is required")
        @Size(max = 4000, message = "Payload body must not exceed 4000 characters")
        String payload
) {
}
