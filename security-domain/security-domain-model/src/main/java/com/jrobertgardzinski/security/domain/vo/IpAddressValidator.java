package com.jrobertgardzinski.security.domain.vo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

class IpAddressValidator {

    private static final Pattern IPV4_PATTERN = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern DIGITS_PATTERN = Pattern.compile("\\d{1,3}");
    private static final Pattern ZONE_ID_PATTERN = Pattern.compile("[^\\s/%]+");

    private static final int IPV6_MAX_HEX_GROUPS = 8;
    private static final int IPV6_MAX_HEX_DIGITS_PER_GROUP = 4;

    static boolean isValid(String address) {
        return isValidIPv4(address) || isValidIPv6(address);
    }

    static boolean isValidIPv4(String address) {
        var matcher = IPV4_PATTERN.matcher(address);
        if (!matcher.matches()) return false;

        for (int i = 1; i <= 4; i++) {
            String octet = matcher.group(i);
            int value = Integer.parseInt(octet);
            if (value > 255) return false;
            if (octet.length() > 1 && octet.startsWith("0")) return false;
        }
        return true;
    }

    private static boolean isValidIPv6(String address) {
        String[] prefixParts = address.split("/", -1);
        if (prefixParts.length > 2) return false;
        if (prefixParts.length == 2) {
            if (!DIGITS_PATTERN.matcher(prefixParts[1]).matches()) return false;
            int bits = Integer.parseInt(prefixParts[1]);
            if (bits < 0 || bits > 128) return false;
        }

        String[] zoneParts = prefixParts[0].split("%", -1);
        if (zoneParts.length > 2) return false;
        if (zoneParts.length == 2 && !ZONE_ID_PATTERN.matcher(zoneParts[1]).matches()) return false;

        String inet6Address = zoneParts[0];

        boolean containsCompressedZeroes = inet6Address.contains("::");
        if (containsCompressedZeroes && inet6Address.indexOf("::") != inet6Address.lastIndexOf("::")) return false;

        boolean startsWithCompressed = inet6Address.startsWith("::");
        boolean endsWithCompressed = inet6Address.endsWith("::");

        if (inet6Address.startsWith(":") && !startsWithCompressed) return false;
        if (inet6Address.endsWith(":") && !endsWithCompressed) return false;

        String[] octets = inet6Address.split(":");
        if (containsCompressedZeroes) {
            List<String> octetList = new ArrayList<>(Arrays.asList(octets));
            if (endsWithCompressed) {
                octetList.add("");
            } else if (startsWithCompressed && !octetList.isEmpty()) {
                octetList.remove(0);
            }
            octets = octetList.toArray(String[]::new);
        }

        if (octets.length > IPV6_MAX_HEX_GROUPS) return false;

        int validOctets = 0;
        int emptyOctets = 0;

        for (int index = 0; index < octets.length; index++) {
            String octet = octets[index];

            if (octet.isEmpty()) {
                emptyOctets++;
                if (emptyOctets > 1) return false;
            } else {
                emptyOctets = 0;

                if (index == octets.length - 1 && octet.contains(".")) {
                    if (!isValidIPv4(octet)) return false;
                    validOctets += 2;
                    continue;
                }

                if (octet.length() > IPV6_MAX_HEX_DIGITS_PER_GROUP) return false;

                try {
                    int value = Integer.parseInt(octet, 16);
                    if (value < 0 || value > 0xFFFF) return false;
                } catch (NumberFormatException e) {
                    return false;
                }
            }
            validOctets++;
        }

        return validOctets <= IPV6_MAX_HEX_GROUPS
                && (validOctets >= IPV6_MAX_HEX_GROUPS || containsCompressedZeroes);
    }
}
