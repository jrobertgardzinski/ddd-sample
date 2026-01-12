package com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication;

import com.jrobertgardzinski.security.domain.vo.security.domain.event.brute.force.protection.ActivateBlockadeEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.brute.force.protection.BlockadeStillActiveEvent;

public sealed interface AuthenticationEvent permits AuthenticationFailedEvent, AuthenticationPassedEvent, WrongEmail, WrongPassword {
}
