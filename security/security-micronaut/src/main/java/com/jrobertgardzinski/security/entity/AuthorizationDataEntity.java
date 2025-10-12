package com.jrobertgardzinski.security.entity;

import com.jrobertgardzinski.security.domain.entity.AuthorizationData;
import com.jrobertgardzinski.security.domain.vo.*;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.Calendar;

@Serdeable
@Entity
public class AuthorizationDataEntity {
    @Id
    private String email;
    private String refreshToken;
    private String authorizationToken;
    private LocalDateTime refreshTokenExpiration;
    private LocalDateTime authorizationTokenExpiration;

    public AuthorizationDataEntity() {
    }

    public AuthorizationDataEntity(String email, String refreshToken, String authorizationToken, LocalDateTime refreshTokenExpiration, LocalDateTime authorizationTokenExpiration) {
        this.email = email;
        this.refreshToken = refreshToken;
        this.authorizationToken = authorizationToken;
        this.refreshTokenExpiration = refreshTokenExpiration;
        this.authorizationTokenExpiration = authorizationTokenExpiration;
    }

    public static AuthorizationDataEntity fromDomain(AuthorizationData authorizationData) {
        return new AuthorizationDataEntity(
                authorizationData.email().value(),
                authorizationData.refreshToken().value().value(),
                authorizationData.authorizationToken().value().value(),
                authorizationData.refreshTokenExpiration().value().value(),
                authorizationData.authorizationTokenExpiration().value().value()
        );
    }

    public AuthorizationData asDomain() {
        return new AuthorizationData(
                new Email(email),
                new RefreshToken(new Token(refreshToken)),
                new AuthorizationToken(new Token(authorizationToken)),
                new RefreshTokenExpiration(new TokenExpiration(refreshTokenExpiration)),
                new AuthorizationTokenExpiration(new TokenExpiration(authorizationTokenExpiration))
        );
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getAuthorizationToken() {
        return authorizationToken;
    }

    public void setAuthorizationToken(String authorizationToken) {
        this.authorizationToken = authorizationToken;
    }

    public LocalDateTime getRefreshTokenExpiration() {
        return refreshTokenExpiration;
    }

    public void setRefreshTokenExpiration(LocalDateTime refreshTokenExpiration) {
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    public LocalDateTime getAuthorizationTokenExpiration() {
        return authorizationTokenExpiration;
    }

    public void setAuthorizationTokenExpiration(LocalDateTime authorizationTokenExpiration) {
        this.authorizationTokenExpiration = authorizationTokenExpiration;
    }
}
