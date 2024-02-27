package dev.yerokha.lorby.controller;

import dev.yerokha.lorby.dto.LoginRequest;
import dev.yerokha.lorby.dto.LoginResponse;
import dev.yerokha.lorby.dto.RegistrationRequest;
import dev.yerokha.lorby.service.AuthService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/auth")
@Slf4j
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/registration")
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegistrationRequest request) {
        log.info("Email: " + request.email());
        log.info("Username: " + request.username());
        log.info("Password: " + request.password());
        authService.createUser(request);
        return new ResponseEntity<>("Registered successfully", HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @GetMapping("/refreshToken")
    public ResponseEntity<String> refreshToken(@RequestBody String refreshToken) {
        log.info(refreshToken);
        return ResponseEntity.ok(authService.refreshToken(refreshToken));
    }
}
