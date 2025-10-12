package com.jrobertgardzinski.security.factory;

import com.jrobertgardzinski.security.domain.factory.SecurityFactory;
import io.micronaut.serde.annotation.SerdeImport;
import jakarta.inject.Singleton;

import java.util.Calendar;

@Singleton
@SerdeImport(Calendar.class)
public class SecurityFactoryAdapter extends SecurityFactory {

}
