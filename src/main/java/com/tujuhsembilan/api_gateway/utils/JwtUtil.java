package com.tujuhsembilan.api_gateway.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.crypto.SecretKey;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Component
public class JwtUtil {

    private String secret = "myverylongandsecurekeywithatleast256bits";

    private long tokenLifeSpan = 60 * 1000;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    public String extractUsernameFromToken(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Boolean validateToken(String token) {
        try {
            Claims claims = extractAllClaims(token); 
            return Objects.nonNull(claims);
        } catch (Exception e) {
            return false;
        }
    }

    public String generateToken(String username, String role) {
         Map<String, Object> claims = new HashMap<>();
         claims.put("role", role);
        return generateToken(claims, username);
    }

    public String generateToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .addClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + tokenLifeSpan))
                .signWith(getSigningKey())
                .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = extractAllClaims(token); // Ekstrak informasi dari token
        String username = claims.getSubject(); // Ambil username dari token
        return new UsernamePasswordAuthenticationToken(
            username, // Principal (biasanya username)
            null, // Credentials (biasanya null untuk JWT)
            Collections.singleton(new SimpleGrantedAuthority(claims.get("role", String.class))) // Roles/authorities
        );
    }

    public List<GrantedAuthority> extractAuthorities(String token) {
        Claims claims = extractAllClaims(token);

        String role = claims.get("role", String.class);
        
        if (role == null) {
            return Collections.emptyList();
        }

        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
        
        return authorities;
    }
}
