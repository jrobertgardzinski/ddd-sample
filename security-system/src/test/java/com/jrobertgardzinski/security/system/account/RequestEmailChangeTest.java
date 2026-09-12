package com.jrobertgardzinski.security.system.account;

import com.jrobertgardzinski.email.config.BlockedDomains;
import com.jrobertgardzinski.email.config.CanRegisterConfig;
import com.jrobertgardzinski.email.domain.DomainPart;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.email.domain.NormalizedEmail;
import com.jrobertgardzinski.security.domain.port.EmailVerificationNotifier;
import com.jrobertgardzinski.security.domain.repository.EmailChangeRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import net.jqwik.api.Example;
import net.jqwik.api.Label;
import net.jqwik.api.lifecycle.BeforeTry;
import org.mockito.Mockito;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

@Epic("Use case")
@Feature("Change email")
class RequestEmailChangeTest {

    private static final Email CURRENT = Email.of("user@example.com");
    private static final Email NEW = Email.of("new@example.com");
    private static final Email BLOCKED = Email.of("user@blocked.example");
    /** The deployment's policy for every example here: one blocked domain, no other rule. */
    private static final CanRegisterConfig EMAIL_POLICY = new CanRegisterConfig(
            new BlockedDomains(Set.of(DomainPart.of("blocked.example"))), null, null);

    private UserRepository userRepository;
    private EmailChangeRepository emailChangeRepository;
    private EmailVerificationNotifier notifier;
    private RequestEmailChange requestEmailChange;

    @BeforeTry
    void init() {
        userRepository = Mockito.mock(UserRepository.class);
        emailChangeRepository = Mockito.mock(EmailChangeRepository.class);
        notifier = Mockito.mock(EmailVerificationNotifier.class);
        requestEmailChange = new RequestEmailChange(userRepository, emailChangeRepository, notifier, EMAIL_POLICY);
    }

    @Example
    @Label("A free new address starts the change and e-mails a link")
    void free_address_starts_the_change() {
        Mockito.when(userRepository.existsBy(NormalizedEmail.of(NEW))).thenReturn(false);

        assertInstanceOf(RequestEmailChangeResult.Requested.class, requestEmailChange.execute(CURRENT, NEW));
        Mockito.verify(emailChangeRepository).startChange(Mockito.any(), Mockito.any());
        Mockito.verify(notifier).sendVerificationLink(Mockito.eq(NEW), Mockito.any());
    }

    @Example
    @Label("An address the deployment does not admit is refused before anything else is asked")
    void the_email_policy_guards_the_change_too() {
        RequestEmailChangeResult result = requestEmailChange.execute(CURRENT, BLOCKED);

        RequestEmailChangeResult.Rejected rejected =
                assertInstanceOf(RequestEmailChangeResult.Rejected.class, result);
        assertEquals(java.util.List.of("DOMAIN_BLOCKED"), rejected.emailErrors());
        // a closed shop that only checks at registration is not closed: the account could walk out
        // through a change, taking its roles, factors and federated links with it
        Mockito.verify(emailChangeRepository, Mockito.never()).startChange(Mockito.any(), Mockito.any());
        Mockito.verify(notifier, Mockito.never()).sendVerificationLink(Mockito.any(), Mockito.any());
        Mockito.verifyNoInteractions(userRepository);
    }

    @Example
    @Label("A taken new address is refused, nothing e-mailed")
    void taken_address_is_refused() {
        Mockito.when(userRepository.existsBy(NormalizedEmail.of(NEW))).thenReturn(true);

        assertInstanceOf(RequestEmailChangeResult.EmailTaken.class, requestEmailChange.execute(CURRENT, NEW));
        Mockito.verify(emailChangeRepository, Mockito.never()).startChange(Mockito.any(), Mockito.any());
        Mockito.verify(notifier, Mockito.never()).sendVerificationLink(Mockito.any(), Mockito.any());
    }
}
