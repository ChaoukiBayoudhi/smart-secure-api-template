package com.example.smartsecure.dto;

public record SecurityAssessmentResponse(
        int riskScore,
        String riskLevel,
        String threatCategory,
        boolean blocked,
        String recommendation
) {
}
