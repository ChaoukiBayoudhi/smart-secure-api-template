package com.example.smartsecure.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "security_audit_logs", indexes = {
        @Index(name = "idx_audit_client_ip", columnList = "clientIp"),
        @Index(name = "idx_audit_created_at", columnList = "createdAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 64)
    private String clientIp;

    @Column(length = 64)
    private String username;

    @Column(nullable = false, length = 16)
    private String httpMethod;

    @Column(nullable = false, length = 255)
    private String requestPath;

    @Column(nullable = false)
    private int riskScore;

    @Column(nullable = false, length = 32)
    private String riskLevel;

    @Column(nullable = false, length = 64)
    private String threatCategory;

    @Column(nullable = false)
    private boolean blocked;

    @Column(length = 1000)
    private String aiAssessment;

    @Column(nullable = false, updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();
}
