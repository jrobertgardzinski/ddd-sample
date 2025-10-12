package com.jrobertgardzinski.security.entity;

import com.jrobertgardzinski.security.domain.entity.FailedAuthentication;
import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.FailedAuthetincationId;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

@Serdeable
@Entity
public class FailedAuthenticationEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;
    private String ipAddress;
    private LocalDateTime time;

    public FailedAuthenticationEntity() {
    }

    public FailedAuthenticationEntity(String ipAddress, LocalDateTime time) {
        this.ipAddress = ipAddress;
        this.time = time;
    }

    public FailedAuthenticationEntity(long id, String ipAddress, LocalDateTime time) {
        this.id = id;
        this.ipAddress = ipAddress;
        this.time = time;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public LocalDateTime getTime() {
        return time;
    }

    public void setTime(LocalDateTime time) {
        this.time = time;
    }


    public static FailedAuthenticationEntity fromDomain(FailedAuthentication failedAuthentication) {
        return new FailedAuthenticationEntity(
                failedAuthentication.id().value(),
                failedAuthentication.details().ipAddress().value(),
                failedAuthentication.details().time()
        );
    }

    public FailedAuthentication asDomain() {
        return new FailedAuthentication(
                new FailedAuthenticationDetails(
                        new IpAddress(ipAddress),
                        time
                ),
                new FailedAuthetincationId(id)
        );
    }
}
