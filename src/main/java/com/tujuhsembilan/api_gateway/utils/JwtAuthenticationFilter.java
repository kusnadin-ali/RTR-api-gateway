package com.tujuhsembilan.api_gateway.utils;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();

        // Skip filter jika request ke /user-service/auth/**
        if (path.startsWith("/auth-service/auth/")) {
            return chain.filter(exchange);
        }
        String token = exchange.getRequest().getHeaders().getFirst("Authorization");

        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);

            if (jwtUtil.validateToken(token)) {
                Claims claims = jwtUtil.extractAllClaims(token);

                log.info(claims.get("role", String.class));

                String role = claims.get("role", String.class).toString();
                Authentication authentication = jwtUtil.getAuthentication(token);
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(authentication);

                ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                        .header("X-Role", "ROLE_" + role.toUpperCase())
                        .build();

                // Teruskan request dengan SecurityContext yang sudah di-set
                return chain.filter(
                        exchange.mutate().request(modifiedRequest).build()).contextWrite(
                                ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
            } else {
                // Token tidak valid, kirim response 401
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        }

        return chain.filter(exchange);
    }
}