package dev.yerokha.lorby;

import dev.yerokha.lorby.entity.Role;
import dev.yerokha.lorby.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class LorbyApplication {

    public static void main(String[] args) {
        SpringApplication.run(LorbyApplication.class, args);
    }

    @Bean
    CommandLineRunner runner(RoleRepository roleRepository) {
        return args -> {
            if (roleRepository.count() > 0) {
                return;
            }

            roleRepository.save(new Role("USER"));
            roleRepository.save(new Role("ADMIN"));
        };
    }

}
