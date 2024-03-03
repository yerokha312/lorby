package dev.yerokha.lorby.config;

import dev.yerokha.lorby.service.TokenService;
import dev.yerokha.lorby.service.UserService;
import dev.yerokha.lorby.util.TokenEncryptionUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static dev.yerokha.lorby.util.RedisCachingUtil.containsKey;
import static dev.yerokha.lorby.util.RedisCachingUtil.getValue;

@Component
@Slf4j
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final UserService userService;
    private final TokenEncryptionUtil encryptionUtil;

    public TokenAuthenticationFilter(TokenService tokenService, UserService userService, TokenEncryptionUtil encryptionUtil) {
        this.tokenService = tokenService;
        this.userService = userService;
        this.encryptionUtil = encryptionUtil;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        final String accessToken = request.getHeader("Authorization");
        if (accessToken == null || !accessToken.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        final String username = tokenService.getUsernameFromToken(accessToken);

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userService.loadUserByUsername(username);

            if (userDetails != null) {
                String key = "access_token:" + username;

                if (containsKey(key)) {
                    String cachedToken = encryptionUtil.decryptToken((String) getValue(key));
                    final String tokenValue = accessToken.substring(7);

                    if (tokenValue.equals(cachedToken)) {
                        UsernamePasswordAuthenticationToken authenticationToken =
                                new UsernamePasswordAuthenticationToken(userDetails, null);
                        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    } else {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        return;
                    }
                } else {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
