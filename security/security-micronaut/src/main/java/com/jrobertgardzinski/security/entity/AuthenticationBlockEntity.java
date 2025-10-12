package com.jrobertgardzinski.security.entity;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

import java.util.Calendar;

@Serdeable
@Entity
public class AuthenticationBlockEntity {
    @Id
    private String ipAddress;
    private Calendar expiryDate;

    public AuthenticationBlockEntity() {
    }

    public AuthenticationBlockEntity(String ipAddress, Calendar expiryDate) {
        this.ipAddress = ipAddress;
        this.expiryDate = expiryDate;
    }

    public static AuthenticationBlockEntity fromDomain(AuthenticationBlock authenticationBlock) {
        return new AuthenticationBlockEntity(
                authenticationBlock.getIpAddress().value(),
                authenticationBlock.getExpiryDate()
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

    public Calendar getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Calendar expiryDate) {
        this.expiryDate = expiryDate;
    }
}
