package dev.yerokha.lorby.controller;

import dev.yerokha.lorby.dto.LoginRequest;
import dev.yerokha.lorby.dto.LoginResponse;
import dev.yerokha.lorby.dto.RegistrationRequest;
import dev.yerokha.lorby.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Tag(name = "Authentication", description = "Controller for reg/login/confirmation etc")
@RestController
@RequestMapping("/v1/auth")
@Slf4j
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @Operation(
            summary = "Registration", description = "Create a new account for user",
            tags = {"authentication", "post"},
            responses = {
                    @ApiResponse(responseCode = "201", description = "Registration success"),
                    @ApiResponse(responseCode = "400", description = "Invalid input"),
                    @ApiResponse(responseCode = "409", description = "Username or email already taken")
            }
    )
    @PostMapping("/registration")
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegistrationRequest request) {
        authService.createUser(request);
        return new ResponseEntity<>("Confirmation link generated, email sent", HttpStatus.CREATED);
    }

    @Operation(
            summary = "Login", description = "Authenticate user and get access & refresh tokens",
            tags = {"authentication", "post"},
            responses = {
                    @ApiResponse(responseCode = "200", description = "User authenticated successfully"),
                    @ApiResponse(responseCode = "401", description = "Invalid username or password", content = @Content),
                    @ApiResponse(responseCode = "401", description = "Not enabled", content = @Content),
            }
    )
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @Operation(
            summary = "Refresh", description = "Obtain a new access token using refresh token",
            tags = {"authentication", "get"},
            responses = {
                    @ApiResponse(responseCode = "200", description = "Access token obtained successfully"),
                    @ApiResponse(responseCode = "401", description = "Invalid token exception", content = @Content)
            }
    )
    @GetMapping("/refresh-token")
    public ResponseEntity<String> refreshToken(@RequestBody String refreshToken) {
        return ResponseEntity.ok(authService.refreshToken(refreshToken));
    }

    @Operation(
            summary = "Confirmation", description = "Confirm email by clicking the sent link " +
            "(https://crazy-zam.github.io/neo-auth/auth/confirmation?ct=)",
            tags = {"authentication", "get"},
            responses = {
                    @ApiResponse(responseCode = "200", description = "Email confirmed successfully"),
                    @ApiResponse(responseCode = "401", description = "Invalid token exception", content = @Content)
            },
            parameters = {
                    @Parameter(name = "ct", description = "Encrypted token value", required = true)
            }

    )
    @GetMapping("/confirmation")
    public ResponseEntity<String> confirmEmail(@RequestParam("ct") String encryptedToken) {
        authService.confirmEmail(encryptedToken);
        return ResponseEntity.ok("Email is confirmed");
    }

    @Operation(
            summary = "Resend mail", description = "Resend mail for user email verification",
            tags = {"authentication", "post"},
            responses = {
                    @ApiResponse(responseCode = "200", description = "Email sent"),
                    @ApiResponse(responseCode = "400", description = "User not found"),
                    @ApiResponse(responseCode = "418", description = "User's email already verified")
            }
    )
    @PostMapping("/resend-confirmation")
    public ResponseEntity<String> resend(@RequestBody Map<String, String> body) {
        authService.sendConfirmationEmail(body);
        return new ResponseEntity<>("Confirmation link generated, email sent", HttpStatus.OK);
    }

    @Operation(
            summary = "Check presence", description = "Endpoint for pre-submit checking free username and email",
            tags = {"authentication", "get"},
            responses = {
                    @ApiResponse(responseCode = "200", description = "Returns true or false")
            }
    )
    @GetMapping("/check-presence")
    public ResponseEntity<Boolean> checkPresence(@RequestBody String username) {
        boolean isPresent = authService.isPresentUsername(username);
        if (isPresent) {
            return ResponseEntity.ok(isPresent);
        }
        isPresent = authService.isPresentEmail(username);
        return ResponseEntity.ok(isPresent);
    }

    @PostMapping("/revoke")
    public ResponseEntity<String> revoke(Authentication authentication, String refreshToken) {
        log.info(refreshToken);
        log.info(authentication.getName());
        authService.revoke(authentication.getName(), refreshToken);
        return ResponseEntity.ok("Logout success");
    }
}
