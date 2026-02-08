package com.jrobertgardzinski;

import com.jrobertgardzinski.security.domain.vo.Email;

/**
 * Hello world!
 *
 */
public class App
{
    public static void main( String[] args )
    {
        Email email = new Email("jrobertgardzinski@wp.pl");
        System.out.println( "Hello " + email + "!" );
    }
}
