package com.early_express.gateway_server.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
		ReactiveJwtAuthenticationConverter conv = new ReactiveJwtAuthenticationConverter();
		conv.setJwtGrantedAuthoritiesConverter(new KeycloakClientRoleConverter());

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
						.pathMatchers("/v1/auth/web/public").permitAll()
                        .anyExchange().authenticated()
                )
				.oauth2ResourceServer(oauth -> oauth.jwt(jwtSpec -> jwtSpec.jwtAuthenticationConverter(conv)))
                .build();
    }
}
