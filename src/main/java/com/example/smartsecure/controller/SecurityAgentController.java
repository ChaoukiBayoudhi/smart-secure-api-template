package com.example.smartsecure.controller;

import com.example.smartsecure.agent.AiSecurityAgentService;
import com.example.smartsecure.domain.SecurityAuditLog;
import com.example.smartsecure.dto.PayloadInspectRequest;
import com.example.smartsecure.dto.SecurityAssessmentResponse;
import com.example.smartsecure.repository.SecurityAuditLogRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/security")
@RequiredArgsConstructor
public class SecurityAgentController {

    private final AiSecurityAgentService aiSecurityAgentService;
    private final SecurityAuditLogRepository auditLogRepository;

    @PostMapping("/inspect")
    @PreAuthorize("hasAnyAuthority('SCOPE_ROLE_ADMIN', 'SCOPE_ROLE_SECURITY_ANALYST')")
    public ResponseEntity<SecurityAssessmentResponse> inspectPayload(
            @Valid @RequestBody PayloadInspectRequest request,
            Authentication authentication
    ) {
        String username = authentication != null ? authentication.getName() : "anonymous";
        SecurityAssessmentResponse response = aiSecurityAgentService.inspectRequest(request, username);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/audit-logs")
    @PreAuthorize("hasAnyAuthority('SCOPE_ROLE_ADMIN', 'SCOPE_ROLE_SECURITY_ANALYST')")
    public ResponseEntity<List<SecurityAuditLog>> getHighRiskAuditLogs(
            @RequestParam(defaultValue = "50") int minRiskScore
    ) {
        return ResponseEntity.ok(
                auditLogRepository.findByRiskScoreGreaterThanEqualOrderByCreatedAtDesc(minRiskScore)
        );
    }
}
