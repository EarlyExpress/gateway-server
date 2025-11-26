package com.early_express.gateway_server.infrastructure.config;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

@Component
public class CustomAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {
	@Override
	public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
		return Mono.fromRunnable(() -> {
			exchange.getResponse().setStatusCode(HttpStatus.FOUND);
			exchange.getResponse().getHeaders().setLocation(URI.create("/v1/auth/web/public/login"));
		});
	}
}
