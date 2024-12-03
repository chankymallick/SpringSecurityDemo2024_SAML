/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.quest.questdemo.config.authproviders;

/**
 *
 * @author MMallick
 */
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.ldap.LdapBindAuthenticationManagerFactory;

import org.springframework.stereotype.Component;

@Component
public class CustomLDAPAuthenticationProvider implements AuthenticationProvider {
    
    String LDAP_URL = "ldap://localhost:10389";
    String USER_DN = "uid=admin,ou=system";
    String LDAP_PASSWORD = "secret";
    String USER_DN_PATTERN = "cn={0},ou=users,ou=system";

    @Autowired
    private AuthenticationManager ldapAuthenticationProvider;

    @Autowired
    private CustomDBAuthenticationProvider customDBAuthenticationProvider;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        try {
            // Try LDAP authentication first
            return ldapAuthenticationProvider.authenticate(authentication);
        } catch (AuthenticationException ex) {
            // If LDAP authentication fails, fall back to DB authentication
            return customDBAuthenticationProvider.authenticate(authentication);
        }
    }

    @Bean
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(contextSource());
    }

    @Bean
    LdapContextSource contextSource() {
        LdapContextSource securityContextSource = new LdapContextSource();
        securityContextSource.setUrl(LDAP_URL);
        securityContextSource.setUserDn(USER_DN);
        securityContextSource.setPassword(LDAP_PASSWORD);
        return securityContextSource;
    }

    @Bean
    AuthenticationManager authmanager(BaseLdapPathContextSource source){
        LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(source);
        factory.setUserDnPatterns(USER_DN_PATTERN);
        return factory.createAuthenticationManager();
    
    }
    
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
