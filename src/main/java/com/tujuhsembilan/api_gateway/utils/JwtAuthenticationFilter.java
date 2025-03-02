package com.tujuhsembilan.api_gateway.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import com.tujuhsembilan.core.utils.JwtUtil;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();

        // Skip filter jika request ke /user-service/auth/**
        if (path.startsWith("/user-service/auth/")) {
            return chain.filter(exchange);
        }
        String token = exchange.getRequest().getHeaders().getFirst("Authorization");

        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            return Mono.just(token)
                    .flatMap(t -> {
                        if (jwtUtil.validateToken(t)) { // Asumsi validateToken mengembalikan boolean
                            Authentication authentication = jwtUtil.getAuthentication(t);
                            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                            securityContext.setAuthentication(authentication);
                            return chain.filter(exchange)
                                    .contextWrite(ReactiveSecurityContextHolder
                                            .withSecurityContext(Mono.just(securityContext)));
                        }
                        return chain.filter(exchange);
                    });
        }

        return chain.filter(exchange);
    }
}