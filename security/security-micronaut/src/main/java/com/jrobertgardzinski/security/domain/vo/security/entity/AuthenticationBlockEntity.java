package com.jrobertgardzinski.security.domain.vo.security.entity;

import com.jrobertgardzinski.security.domain.vo.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

import java.time.LocalDateTime;

@Serdeable
@Entity
public class AuthenticationBlockEntity {
    @Id
    private String ipAddress;
    private LocalDateTime expiryDate;

    public AuthenticationBlockEntity() {
    }

    public AuthenticationBlockEntity(String ipAddress, LocalDateTime expiryDate) {
        this.ipAddress = ipAddress;
        this.expiryDate = expiryDate;
    }

    public static AuthenticationBlockEntity fromDomain(AuthenticationBlock authenticationBlock) {
        return new AuthenticationBlockEntity(
                authenticationBlock.ipAddress().value(),
                authenticationBlock.expiryDate()
        );
    }

    public AuthenticationBlock asDomain() {
        return new AuthenticationBlock(
                new IpAddress(ipAddress),
                expiryDate);
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public LocalDateTime getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(LocalDateTime expiryDate) {
        this.expiryDate = expiryDate;
    }
}
