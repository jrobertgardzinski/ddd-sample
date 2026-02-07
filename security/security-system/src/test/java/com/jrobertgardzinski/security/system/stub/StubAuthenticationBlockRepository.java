package com.jrobertgardzinski.security.system.stub;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.vo.IpAddress;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class StubAuthenticationBlockRepository implements AuthenticationBlockRepository {

    private final Map<IpAddress, AuthenticationBlock> blocks = new HashMap<>();

    @Override
    public AuthenticationBlock create(AuthenticationBlock authenticationBlock) {
        blocks.put(authenticationBlock.ipAddress(), authenticationBlock);
        return authenticationBlock;
    }

    @Override
    public void removeAllFor(IpAddress ipAddress) {
        blocks.remove(ipAddress);
    }

    @Override
    public Optional<AuthenticationBlock> findBy(IpAddress ipAddress) {
        return Optional.ofNullable(blocks.get(ipAddress));
    }
}
