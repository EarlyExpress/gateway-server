package com.early_express.gateway_server.infrastructure.config;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Objects;

@Component
public class AddUserHeaderGlobalFilter implements GlobalFilter, Ordered {
	private static final String HEADER_USER_ID = "X-User-Id";
	private static final String HEADER_USERNAME = "X-Username";
	private static final String HEADER_ROLE = "X-User-Role";
	private static final String HEADER_EMAIL = "X-User-Email";
	private static final String HEADER_AUTHORIZATION = "Authorization";
	private static final String BEARER_PREFIX = "Bearer ";

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext()
											.map(context -> context == null ? null : context.getAuthentication())
											.flatMap(auth -> {
												if (!(auth instanceof JwtAuthenticationToken)) {
													return chain.filter(exchange);
												}

												Jwt token = ((JwtAuthenticationToken) auth).getToken();
												String role = extractRole(token);

												ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
																						   .header(HEADER_USER_ID, Objects.requireNonNullElse(token.getClaimAsString("user_id"), ""))
																						   .header(HEADER_USERNAME, Objects.requireNonNullElse(token.getClaimAsString("username"), ""))
																						   .header(HEADER_ROLE, role)
																						   .header(HEADER_EMAIL, Objects.requireNonNullElse(token.getClaimAsString("email"), ""))
																						   .header(HEADER_AUTHORIZATION, BEARER_PREFIX + token.getTokenValue())
																						   .build();

												ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();
												return chain.filter(mutatedExchange);
											})
											.switchIfEmpty(chain.filter(exchange))	// SecurityContext가 없을 때 기본 동작
											.onErrorResume(ex -> chain.filter(exchange)); // 오류 발생 시 fallback
	}

	@Override
	public int getOrder() {
		return Ordered.HIGHEST_PRECEDENCE;
	}

	private String extractRole(Jwt token) {
		String role = "";

		if (token.hasClaim("roles")) {
			Object roles = token.getClaim("roles");
			if (roles instanceof Collection<?> roleList) {
				role = roleList.stream()
							   .map(Object::toString)
							   .filter(r -> r.startsWith("ROLE_"))
							   .findFirst().orElse("");
			}
		}

		return role;
	}
}
