package com.auth0.samples.authapi.springbootauthupdated.security;

public class SecurityConstants {

    static final long EXPIRATION_TIME = 864_000_000;
    static final String SECRET = "SecretKeyToGenJWTs";
    static final String HEADER_STRING = "Authorization";
    static final String TOKEN_PREFIX = "Bearer ";
    static final String SIGN_UP_URL = "/users/sign-up";




}
