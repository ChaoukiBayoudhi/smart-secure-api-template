package com.example.smartsecure.security;

import com.example.smartsecure.domain.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JwtTokenService {

    private final JwtEncoder jwtEncoder;

    @Value("${app.security.jwt.issuer:self}")
    private String issuer;

    @Value("${app.security.jwt.access-token-ttl-minutes:15}")
    private long accessTokenTtlMinutes;

    public String generateAccessToken(String username, Set<Role> roles) {
        Instant now = Instant.now();
        String scope = roles.stream()
                .map(Enum::name)
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(now)
                .expiresAt(now.plus(accessTokenTtlMinutes, ChronoUnit.MINUTES))
                .subject(username)
                .claim("scope", scope)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public long getAccessTokenTtlSeconds() {
        return accessTokenTtlMinutes * 60;
    }
}
