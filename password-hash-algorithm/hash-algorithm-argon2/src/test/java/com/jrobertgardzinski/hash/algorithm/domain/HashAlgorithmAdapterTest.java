package com.jrobertgardzinski.hash.algorithm.domain;

class HashAlgorithmAdapterTest extends HashAlgorithmPortTest {
    @Override
    protected HashAlgorithmPort hashAlgorithm() {
        return new HashAlgorithmAdapter();
    }
}

