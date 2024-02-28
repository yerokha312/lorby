package dev.yerokha.lorby.service;

import dev.yerokha.lorby.dto.LoginRequest;
import dev.yerokha.lorby.dto.LoginResponse;
import dev.yerokha.lorby.dto.RegistrationRequest;
import dev.yerokha.lorby.entity.UserEntity;
import dev.yerokha.lorby.exception.EmailAlreadyTakenException;
import dev.yerokha.lorby.exception.UsernameAlreadyTakenException;
import dev.yerokha.lorby.repository.RoleRepository;
import dev.yerokha.lorby.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
        if (userRepository.findByUsernameIgnoreCase(username).isPresent()) {
            throw new UsernameAlreadyTakenException(String.format("Username %s already taken", username));
        }

        String email = request.email();
        if (userRepository.findByEmail(email).isPresent()) {
            throw new EmailAlreadyTakenException(String.format("Email %s already taken", email));
        }
        UserEntity entity = new UserEntity(
                username,
                email.toLowerCase(),
                passwordEncoder.encode(request.password()),
                Set.of(roleRepository.findByAuthority("USER"))
        );
        String link = "http://localhost:8080/v1/auth/confirmation";

        String confirmationToken = tokenService.generateConfirmationToken(entity);
        log.info("AuthService: Encrypted token: " + confirmationToken);
        mailService.send(entity.getEmail(), "Email confirmation",
                "Here is your confirmation link: " + link + "?ct=" + confirmationToken);

        userRepository.save(entity);
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
        log.info("AuthService: Encrypted token: " + encryptedToken);
        String username = tokenService.confirmationTokenIsValid(encryptedToken);
        log.info("AuthService: username: " + username);
        userRepository.enableUser(username);
    }
}
