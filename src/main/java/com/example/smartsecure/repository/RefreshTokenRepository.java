package com.example.smartsecure.repository;

import com.example.smartsecure.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenDigestAndRevokedFalse(String tokenDigest);

    @Modifying
    @Query("UPDATE RefreshToken r SET r.revoked = true WHERE r.user.id = :userId")
    int revokeAllByUserId(UUID userId);
}
