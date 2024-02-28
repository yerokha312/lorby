package dev.yerokha.lorby.repository;

import dev.yerokha.lorby.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface TokenRepository extends JpaRepository<RefreshToken, Long> {

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.userEntity.username = :username AND rt.isRevoked = false")
    List<RefreshToken> findNotRevokedByUsername(String username);
}
