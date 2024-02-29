package dev.yerokha.lorby.service;

import dev.yerokha.lorby.dto.LoginRequest;
import dev.yerokha.lorby.dto.LoginResponse;
import dev.yerokha.lorby.dto.RegistrationRequest;
import dev.yerokha.lorby.entity.UserEntity;
import dev.yerokha.lorby.exception.EmailAlreadyTakenException;
import dev.yerokha.lorby.exception.UserAlreadyEnabledException;
import dev.yerokha.lorby.exception.UsernameAlreadyTakenException;
import dev.yerokha.lorby.repository.RoleRepository;
import dev.yerokha.lorby.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Set;

@Service
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final MailService mailService;
    @Value("${LINK}")
    private String link;

    public AuthService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder,
                       TokenService tokenService,
                       AuthenticationManager authenticationManager, MailService mailService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
        this.mailService = mailService;
    }

    public void createUser(RegistrationRequest request) {
        String username = request.username();
        if (isPresentUsername(username)) {
            throw new UsernameAlreadyTakenException(String.format("Username %s already taken", username));
        }

        String email = request.email();
        if (isPresentEmail(email)) {
            throw new EmailAlreadyTakenException(String.format("Email %s already taken", email));
        }
        UserEntity entity = new UserEntity(
                username,
                email.toLowerCase(),
                passwordEncoder.encode(request.password()),
                Set.of(roleRepository.findByAuthority("USER"))
        );

        userRepository.save(entity);

        sendConfirmationEmail(Map.of("username", username, "email", email));
    }

    public boolean isPresentEmail(String email) {
        return userRepository.findByEmailIgnoreCase(email).isPresent();
    }

    public boolean isPresentUsername(String username) {
        return userRepository.findByUsernameIgnoreCase(username).isPresent();
    }

    public void sendConfirmationEmail(Map<String, String> body) {
        UserEntity entity = userRepository.findByUsernameOrEmail(
                body.get("username"), body.get("email")).orElseThrow(() ->
                new UsernameNotFoundException("User not found"));
        if (entity.isEnabled()) {
            throw new UserAlreadyEnabledException("User has already confirmed email address");
        }
        String confirmationToken = tokenService.generateConfirmationToken(entity);
        mailService.sendConfirmationEmail(entity.getEmail(),
                link + "?ct=" + confirmationToken);
    }

    public LoginResponse login(LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password()));

            UserEntity entity = (UserEntity) authentication.getPrincipal();
            return new LoginResponse(
                    tokenService.generateAccessToken(entity),
                    tokenService.generateRefreshToken(entity)
            );

        } catch (AuthenticationException e) {
            if (e instanceof DisabledException) {
                throw new DisabledException("Account has not been enabled");
            } else {
                throw new BadCredentialsException("Invalid username or password");
            }
        }
    }

    public String refreshToken(String refreshToken) {
        return tokenService.refreshAccessToken(refreshToken);
    }

    @Transactional
    public void confirmEmail(String encryptedToken) {
        String username = tokenService.confirmationTokenIsValid(encryptedToken);
        userRepository.enableUser(username);
    }

    public void revoke(String refreshToken) {
        tokenService.revokeRefreshToken(refreshToken);
    }
}
