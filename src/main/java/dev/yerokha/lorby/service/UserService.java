package dev.yerokha.lorby.service;

import dev.yerokha.lorby.dto.User;
import dev.yerokha.lorby.entity.UserEntity;
import dev.yerokha.lorby.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        return userRepository.findByUsernameOrEmail(username, username).orElseThrow(() ->
                new UsernameNotFoundException("User not found"));
    }

    public User getUser(String username) {
        UserEntity entity = (UserEntity) loadUserByUsername(username);
        return new User(entity.getUsername(), entity.getEmail());
    }

}
