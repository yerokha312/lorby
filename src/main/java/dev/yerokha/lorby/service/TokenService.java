package dev.yerokha.lorby.service;

import dev.yerokha.lorby.entity.RefreshToken;
import dev.yerokha.lorby.entity.UserEntity;
import dev.yerokha.lorby.enums.TokenType;
import dev.yerokha.lorby.exception.InvalidTokenException;
import dev.yerokha.lorby.repository.TokenRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static dev.yerokha.lorby.util.TokenEncryptionUtil.decryptToken;
import static dev.yerokha.lorby.util.TokenEncryptionUtil.encryptToken;

@Slf4j
@Service
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final TokenRepository tokenRepository;
    private static final int expirationMinutes = 5;
    private static final int ACCESS_TOKEN_EXPIRATION = expirationMinutes * 3;
    private static final int REFRESH_TOKEN_EXPIRATION = expirationMinutes * 12 * 24 * 7;

    public TokenService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, TokenRepository tokenRepository) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.tokenRepository = tokenRepository;
    }

    public String generateConfirmationToken(UserEntity entity) {
        return encryptToken("Bearer " + generateToken(entity, expirationMinutes, TokenType.CONFIRMATION));
    }

    public String generateAccessToken(UserEntity entity) {
        return generateToken(entity, ACCESS_TOKEN_EXPIRATION, TokenType.ACCESS);
    }

    public String generateRefreshToken(UserEntity entity) {
        String token = generateToken(entity, REFRESH_TOKEN_EXPIRATION, TokenType.REFRESH);
        String encryptedToken = encryptToken("Bearer " + token);
        log.info("Encrypted token: " + encryptedToken);
        RefreshToken refreshToken = new RefreshToken(
                encryptedToken,
                entity,
                Instant.now(),
                Instant.now().plus(REFRESH_TOKEN_EXPIRATION, ChronoUnit.MINUTES)
        );
        tokenRepository.save(refreshToken);
        return token;
    }

    private String generateToken(UserEntity entity, int expirationTime, TokenType tokenType) {
        log.info(String.valueOf(expirationTime));
        Instant now = Instant.now();
        String scopes = getScopes(entity);

        JwtClaimsSet claims = getClaims(now, expirationTime, entity.getUsername(), scopes, tokenType);
        String token = encodeToken(claims);

        log.info("Generated {} token for user {}", token, entity.getUsername());

        return token;
    }

    private String getScopes(UserEntity entity) {
        return entity.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
    }

    private JwtClaimsSet getClaims(Instant now, long expirationTime, String subject, String scopes, TokenType tokenType) {
        return JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(expirationTime, ChronoUnit.MINUTES))
                .subject(subject)
                .claim("scopes", scopes)
                .claim("tokenType", tokenType)
                .build();
    }

    private String encodeToken(JwtClaimsSet claims) {
        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

//    public String getUsernameFromToken(String token) {
//        return decodeToken(token).getSubject();
//    }

    private Jwt decodeToken(String token) {
        if (!token.startsWith("Bearer ")) {
            throw new InvalidTokenException("Invalid token format");
        }

        String strippedToken = token.substring(7);

        try {
            return jwtDecoder.decode(strippedToken);
        } catch (JwtException e) {
            throw new InvalidTokenException("Invalid token");
        }
    }

    public String refreshAccessToken(String refreshToken) {
        Jwt decodedToken = decodeToken(refreshToken);
        String username = decodedToken.getSubject();
        if (!decodedToken.getClaim("tokenType").equals(TokenType.REFRESH.name())) {
            throw new InvalidTokenException("Invalid token type");
        }

        if (isExpired(decodedToken)) {
            throw new InvalidTokenException("Refresh token expired");
        }

        if (isRevoked(refreshToken, username)) {
            throw new InvalidTokenException("Token is revoked");
        }

        Instant now = Instant.now();
        String subject = decodedToken.getSubject();
        String scopes = decodedToken.getClaim("scopes");
        JwtClaimsSet claims = getClaims(now, ACCESS_TOKEN_EXPIRATION, subject, scopes, TokenType.ACCESS);
        log.info("Generated new access token for user {}", subject);
        return encodeToken(claims);

    }

    private boolean isRevoked(String refreshToken, String username) {
        List<RefreshToken> tokenList = tokenRepository.findNotRevokedByUsername(username);
        if (tokenList.isEmpty()) {
            return true;
        }

        for (RefreshToken token : tokenList) {
            if (refreshToken.equals(decryptToken(token.getToken()))) {
                return false;
            }
        }

        return true;
    }

    private boolean isExpired(Jwt decodedToken) {
        return Objects.requireNonNull(decodedToken.getExpiresAt()).isBefore(Instant.now());
    }

    public String confirmationTokenIsValid(String encryptedToken) {
        String confirmationToken = decryptToken(encryptedToken);
        Jwt decodedToken = decodeToken(confirmationToken);
        if (!decodedToken.getClaim("tokenType").equals(TokenType.CONFIRMATION.name())) {
            throw new InvalidTokenException("Invalid token type");
        }

        if (isExpired(decodedToken)) {
            throw new InvalidTokenException("Confirmation link is expired");
        }

        return decodedToken.getSubject();
    }
}
