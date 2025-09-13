package com.example.keycloakspring;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.core.convert.converter.Converter;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .authorizeExchange(auth -> auth
                        .pathMatchers("/public/**", "/actuator/health", "/actuator/info").permitAll()
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(keycloakJwtAuthConverterReactive()))
                )
                .build();
    }


    private Converter<Jwt, Mono<JwtAuthenticationToken>> keycloakJwtAuthConverterReactive() {
        return jwt -> {
            Set<String> roles = new HashSet<>();

            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null) {
                Object r = realmAccess.get("roles");
                if (r instanceof Collection<?> col) {
                    col.forEach(o -> { if (o != null) roles.add(o.toString()); });
                }
            }

            Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
            if (resourceAccess instanceof Map<?, ?> resAcc) {
                for (Object entryObj : resAcc.values()) {
                    if (entryObj instanceof Map<?, ?> clientMap) {
                        Object cr = clientMap.get("roles");
                        if (cr instanceof Collection<?> col) {
                            col.forEach(o -> { if (o != null) roles.add(o.toString()); });
                        }
                    }
                }
            }

            Collection<GrantedAuthority> authorities = roles.stream()
                    .filter(r -> !r.isBlank())
                    .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());

            return Mono.just(new JwtAuthenticationToken(jwt, authorities));
        };
    }
}