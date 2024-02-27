package dev.yerokha.lorby.repository;

import dev.yerokha.lorby.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByUserEntityUsername(String username);

}
