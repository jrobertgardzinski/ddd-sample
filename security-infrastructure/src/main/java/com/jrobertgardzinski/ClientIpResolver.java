package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.IpAddress;
import io.micronaut.context.annotation.Value;
import io.micronaut.http.HttpRequest;
import jakarta.inject.Singleton;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Resolves the {@link IpAddress} that brute-force protection treats as the request's source.
 *
 * <p>The source is the brute-force key and the key of every throttle, so it must be hard to spoof:
 * {@code X-Forwarded-For} is honoured <em>only</em> when the request actually arrived from a
 * configured trusted proxy (load balancer / reverse proxy); otherwise the connection's remote
 * address is used. This stops a client from forging an arbitrary source — and thus dodging its own
 * lockout — by sending an {@code X-Forwarded-For} header directly. Trusted proxies are configured
 * via {@code security.trusted-proxies} (a comma-separated list; empty by default).
 *
 * <p><b>Which element of the header is the client?</b> The rightmost one that is not ours. A proxy
 * APPENDS the peer it saw (nginx's {@code $proxy_add_x_forwarded_for}, ingress-nginx, Traefik), so
 * the list reads client, proxy, proxy — and everything to the LEFT of our own infrastructure is
 * whatever the caller chose to send. Taking the leftmost element therefore handed the caller its
 * own throttle key: rotate it and no limit ever bites, or write a victim's address and spend the
 * victim's failure window for them. So this walks the list from the right, skips every element that
 * is a trusted proxy of ours, and takes the first one that is not — falling back to the peer when
 * the list is empty, all trusted, or the candidate is not an IP address at all (a header saying
 * {@code unknown} used to reach the {@code IpAddress} constructor and answer 500 on every throttled
 * endpoint).
 *
 * <p>Entries are compared as exact addresses: a CIDR block in {@code security.trusted-proxies}
 * matches nothing. A deployment behind Kubernetes must therefore name the ingress pod addresses,
 * not the pod network.
 *
 * <p>An address is also CANONICALISED before it becomes anybody's key: the IPv6 zone id (the
 * {@code %eth0} part) is a hint about the local machine's interfaces, not about who is calling, and
 * the domain's validator accepts one of any length — which then does not fit the {@code VARCHAR(64)}
 * the failure log keys on. Two sources that differ only by zone id were also two different keys,
 * which is one throttle bucket each.
 */
@Singleton
public class ClientIpResolver {

    private final Set<String> trustedProxies;

    public ClientIpResolver(@Value("${security.trusted-proxies:}") List<String> trustedProxies) {
        this.trustedProxies = trustedProxies == null ? Set.of()
                : trustedProxies.stream()
                        .filter(proxy -> !proxy.isBlank())
                        .map(String::trim)
                        .collect(Collectors.toUnmodifiableSet());
    }

    /** The width of every column an address is stored in ({@code VARCHAR(64)}, V1 and V9). */
    private static final int ADDRESS_COLUMN_WIDTH = 64;

    public IpAddress resolve(HttpRequest<?> request) {
        String remoteAddress = canonical(request.getRemoteAddress().getAddress().getHostAddress());
        if (!trustedProxies.contains(remoteAddress)) {
            return new IpAddress(remoteAddress);   // the peer spoke for itself
        }
        String forwardedFor = request.getHeaders().get("X-Forwarded-For");
        if (forwardedFor == null || forwardedFor.isBlank()) {
            return new IpAddress(remoteAddress);
        }
        String[] hops = forwardedFor.split(",");
        for (int hop = hops.length - 1; hop >= 0; hop--) {
            String candidate = canonical(hops[hop].trim());
            if (trustedProxies.contains(candidate)) {
                continue;   // our own hop: keep walking left
            }
            return parsed(candidate).orElseGet(() -> new IpAddress(remoteAddress));
        }
        return new IpAddress(remoteAddress);   // nothing but our own proxies in the list
    }

    /** The address, or empty when the element is not one — the caller writes this header. */
    private static Optional<IpAddress> parsed(String candidate) {
        if (candidate.length() > ADDRESS_COLUMN_WIDTH) {
            // it would not fit the column the brute-force log keys on, and a source that cannot be
            // recorded cannot be limited either — so it is not allowed to become the key
            return Optional.empty();
        }
        try {
            return Optional.of(new IpAddress(candidate));
        } catch (IllegalArgumentException notAnAddress) {
            return Optional.empty();
        }
    }

    /**
     * The address without its IPv6 zone id — {@code fe80::1%eth0} is the same caller as
     * {@code fe80::1}, and the suffix names an interface on THIS machine.
     */
    private static String canonical(String address) {
        int zone = address.indexOf('%');
        return zone < 0 ? address : address.substring(0, zone);
    }
}
