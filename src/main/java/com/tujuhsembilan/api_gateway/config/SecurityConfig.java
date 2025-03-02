package com.tujuhsembilan.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import com.tujuhsembilan.api_gateway.utils.JwtAuthenticationFilter;
import com.tujuhsembilan.core.utils.JwtUtil;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    // Bean untuk JwtUtil
    @Bean
    JwtUtil jwtUtil() {
        return new JwtUtil();
    }

    // Bean untuk JwtAuthenticationFilter
    @Bean
    JwtAuthenticationFilter jwtAuthenticationFilter(JwtUtil jwtUtil) {
        return new JwtAuthenticationFilter(jwtUtil);
    }

    // Konfigurasi SecurityWebFilterChain
    @Bean
    SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http, JwtAuthenticationFilter jwtFilter) {
        return http
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/user-service/auth/**").permitAll() // Izinkan tanpa token
                        .anyExchange().authenticated() // Lainnya wajib terautentikasi
                )
                .addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .httpBasic().disable()
                .formLogin().disable()
                .csrf().disable()
                .build();
    }
}