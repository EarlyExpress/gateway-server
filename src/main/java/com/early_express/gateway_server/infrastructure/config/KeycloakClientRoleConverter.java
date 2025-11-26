package com.early_express.gateway_server.infrastructure.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;

import java.util.Collection;

public class KeycloakClientRoleConverter implements Converter<Jwt, Flux<GrantedAuthority>> {

	@Override
	public Flux<GrantedAuthority> convert(Jwt jwt) {
		Object roles = jwt.getClaims().get("roles");

		if (roles instanceof Collection<?>) {
			return Flux.fromIterable((Collection<?>) roles)
					   .map(Object::toString)
					   .filter(role -> role.startsWith("ROLE_"))
					   .map(SimpleGrantedAuthority::new);
		}

		return Flux.empty();
	}
}
