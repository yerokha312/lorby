package dev.yerokha.lorby;

import dev.yerokha.lorby.entity.Role;
import dev.yerokha.lorby.entity.UserEntity;
import dev.yerokha.lorby.repository.RoleRepository;
import dev.yerokha.lorby.repository.TokenRepository;
import dev.yerokha.lorby.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.Set;

@SpringBootApplication
public class LorbyApplication {

    public static void main(String[] args) {
        SpringApplication.run(LorbyApplication.class, args);
    }

    @Bean
    CommandLineRunner runner(RoleRepository roleRepository, UserRepository userRepository, TokenRepository tokenRepository) {
        return args -> {
            tokenRepository.deleteAll();
            if (roleRepository.count() > 0) {
                return;
            }

            Role userRole = roleRepository.save(new Role("USER"));
            roleRepository.save(new Role("ADMIN"));

            userRepository.save(
                    new UserEntity(
                            "testuser",
                            "test@test.com",
                            "$2a$10$X50gHdTxTmHkehTdwQoUpuQzK8fyka8EZiw0/h3svkXr/aYeYMtpC",
                            true,
                            Set.of(userRole)
                    )
            );
        };
    }

}
