package com.example.keycloakspring;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.oauth2.jwt.Jwt;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(c -> {})
                .csrf(csrf ->csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }

    private org.springframework.core.convert.converter.Converter<Jwt, ? extends AbstractAuthenticationToken> keycloakJwtAuthConverter() {
        return jwt -> {
            Set<String> roles = new HashSet<>();

            
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null) {
                Object r = realmAccess.get("roles");
                if (r instanceof Collection<?> col) {
                    for (Object o : col) {
                        if (o != null)
                            roles.add(o.toString());
                    }
                }
            }

            
            Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
            if (resourceAccess instanceof Map<?, ?> resAcc) {
                for (Object entryObj : resAcc.values()) { // recorre cada client
                    if (entryObj instanceof Map<?, ?> clientMap) {
                        Object cr = clientMap.get("roles");
                        if (cr instanceof Collection<?> col) {
                            for (Object o : col) {
                                if (o != null)
                                    roles.add(o.toString());
                            }
                        }
                    }
                }
            }

           
            Collection<GrantedAuthority> authorities = roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .collect(Collectors.toSet());

            return new JwtAuthenticationToken(jwt, authorities);
        };
    }
}