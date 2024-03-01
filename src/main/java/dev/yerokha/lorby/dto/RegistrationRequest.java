package dev.yerokha.lorby.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import org.hibernate.validator.constraints.Length;

public record RegistrationRequest(
        @Email
        String email,
        @Length(min = 6, max = 20, message = "Username length should be between 6 and 20 characters")
        @Pattern(regexp = "^[a-zA-Z]{6,20}$",
                message = "Username must consist of 6-20 latin letters")
        String username,
        @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-={}:;.,<>/?]).{8,15}$")
        String password,
        String endpoint
) {
}
