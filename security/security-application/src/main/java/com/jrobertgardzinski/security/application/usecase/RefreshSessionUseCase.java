package com.jrobertgardzinski.security.application.usecase;

import com.jrobertgardzinski.security.system.feature.RefreshSession;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenEvent;
import com.jrobertgardzinski.security.domain.vo.SessionRefreshRequest;

public class RefreshSessionUseCase {
    private final RefreshSession refreshSession;

    public RefreshSessionUseCase(RefreshSession refreshSession) {
        this.refreshSession = refreshSession;
    }

    public RefreshTokenEvent execute(SessionRefreshRequest sessionRefreshRequest) {
        return refreshSession.apply(sessionRefreshRequest);
    }
}
