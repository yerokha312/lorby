package dev.yerokha.lorby.controller;

import dev.yerokha.lorby.dto.EmailAndUsername;
import dev.yerokha.lorby.dto.LoginRequest;
import dev.yerokha.lorby.dto.LoginResponse;
import dev.yerokha.lorby.dto.RegistrationRequest;
import dev.yerokha.lorby.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

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
            tags = {"authentication", "post"},
            responses = {
                    @ApiResponse(responseCode = "200", description = "Access token obtained successfully"),
                    @ApiResponse(responseCode = "401", description = "Invalid token exception", content = @Content)
            }
    )
    @PostMapping("/refresh-token")
    public ResponseEntity<String> refreshToken(@RequestBody String refreshToken) {
        return ResponseEntity.ok(authService.refreshToken(refreshToken));
    }

    @Operation(
            summary = "Confirmation", description = "Confirm email by clicking the sent link " +
            "({https://crazy-zam.github.io/neo-auth/auth/}confirmation?ct=)",
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
    public ResponseEntity<String> resend(@RequestBody @Valid EmailAndUsername request) {
        authService.sendConfirmationEmail(request);
        return new ResponseEntity<>("Confirmation link generated, email sent", HttpStatus.OK);
    }

    @Operation(
            summary = "Check presence",
            description = "Endpoint for pre-submit checking of available username and email. False if available",
            tags = {"authentication", "post"},
            responses = {
                    @ApiResponse(responseCode = "200", description = "Returns true or false")
            }
    )
    @PostMapping("/check-presence")
    public ResponseEntity<Boolean> checkPresence(@RequestBody @Valid EmailAndUsername emailAndUsername) {
        boolean isPresent = authService.isPresentUsername(emailAndUsername.username());
        if (isPresent) {
            return ResponseEntity.ok(isPresent);
        }
        isPresent = authService.isPresentEmail(emailAndUsername.email());
        return ResponseEntity.ok(isPresent);
    }

    @Operation(
            summary = "Revoke refresh token", description = "Accepts plain refresh token string for further revocation",
            tags = {"authentication", "post"},
            responses = {
                    @ApiResponse(responseCode = "200", description = "Revocation success"),
                    @ApiResponse(responseCode = "401", description = "Invalid token")
            }
    )
    @PostMapping("/revoke-token")
    public ResponseEntity<String> revoke(@RequestBody String refreshToken, HttpServletRequest request) {
        authService.revoke(refreshToken, request);
        return ResponseEntity.ok("Logout success");
    }

    @Operation(
            summary = "Forgot password", description = "Send confirmation email for password reset" +
            "({https://crazy-zam.github.io/neo-auth/auth/}reset-password?rpt=)",
            tags = {"authentication", "post"},
            responses = {
                    @ApiResponse(responseCode = "200", description = "Email sent or user not found")
            }
    )
    @PostMapping("/forgot-password")
    public ResponseEntity<String> findUser(@RequestBody @Valid EmailAndUsername usernameOrEmail) {
        authService.sendResetPasswordEmail(usernameOrEmail);
        return ResponseEntity.ok("Confirmation link generated, email sent");
    }

    @Operation(
            summary = "Reset password", description = "Verifies sent token and resets password for a new one",
            tags = {"authentication", "put"},
            responses = {
                    @ApiResponse(responseCode = "200", description = "Password reset successfully"),
                    @ApiResponse(responseCode = "400", description = "Invalid input"),
                    @ApiResponse(responseCode = "401", description = "Username from token does not match")
            }
    )
    @PutMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestParam("rpt") String encryptedToken,
                                                @RequestBody @Valid RegistrationRequest request) {
        authService.resetPassword(request.password(), encryptedToken);
        return ResponseEntity.ok("Password reset");
    }
}
