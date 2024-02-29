package dev.yerokha.lorby.controller;

import dev.yerokha.lorby.dto.User;
import dev.yerokha.lorby.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "User", description = "Controller for users operations")
@RestController
@RequestMapping("/v1/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @Operation(
            summary = "Get profile page", description = "Secured endpoint with user info",
            tags = {"user", "get"},
            responses = {
                    @ApiResponse(responseCode = "200", description = "Request success"),
                    @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content),
                    @ApiResponse(responseCode = "404", description = "User not found", content = @Content)
            }
    )
    @GetMapping
    public ResponseEntity<User> showProfile(Authentication authentication) {
        return ResponseEntity.ok(userService.getUser(authentication.getName()));
    }
}
