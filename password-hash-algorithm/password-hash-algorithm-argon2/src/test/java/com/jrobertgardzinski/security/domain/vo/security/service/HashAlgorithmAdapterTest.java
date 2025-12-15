package com.jrobertgardzinski.security.domain.vo.security.service;

import com.jrobertgardzinski.security.domain.vo.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.vo.hash.algorithm.domain.HashAlgorithmPortTest;

class HashAlgorithmAdapterTest extends HashAlgorithmPortTest {
    @Override
    protected HashAlgorithmPort hashAlgorithm() {
        return new HashAlgorithmAdapter();
    }
}

