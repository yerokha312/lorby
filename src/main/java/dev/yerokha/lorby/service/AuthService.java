package dev.yerokha.lorby.service;

import dev.yerokha.lorby.dto.LoginRequest;
import dev.yerokha.lorby.dto.LoginResponse;
import dev.yerokha.lorby.dto.RegistrationRequest;
import dev.yerokha.lorby.entity.UserEntity;
import dev.yerokha.lorby.repository.RoleRepository;
import dev.yerokha.lorby.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;

    public AuthService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder,
                       TokenService tokenService,
                       AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
    }

    public void createUser(RegistrationRequest request) {
        UserEntity entity = new UserEntity(
                request.username(),
                request.email(),
                passwordEncoder.encode(request.password()),
                Set.of(roleRepository.findByAuthority("USER"))
        );

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
}
