package com.example.smartsecure.agent;

import com.example.smartsecure.domain.SecurityAuditLog;
import com.example.smartsecure.repository.RefreshTokenRepository;
import com.example.smartsecure.repository.SecurityAuditLogRepository;
import com.example.smartsecure.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@RequiredArgsConstructor
public class SecurityTools {

    private final SecurityAuditLogRepository auditLogRepository;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    @Tool(description = "Fetch the 20 most recent security audit logs for a given client IP address to detect brute-force or repeated attack patterns.")
    public List<SecurityAuditLog> getRecentAuditLogsByIp(String clientIp) {
        return auditLogRepository.findTop20ByClientIpOrderByCreatedAtDesc(clientIp);
    }

    @Tool(description = "Lock a user account and revoke all active refresh tokens when high-confidence credential compromise or malicious abuse is detected.")
    @Transactional
    public String lockCompromisedUserAccount(String username) {
        return userRepository.findByUsername(username)
                .map(user -> {
                    user.setAccountLocked(true);
                    userRepository.save(user);
                    int revokedCount = refreshTokenRepository.revokeAllByUserId(user.getId());
                    return "Locked account '" + username + "' and revoked " + revokedCount + " active refresh tokens.";
                })
                .orElse("User '" + username + "' not found.");
    }
}
