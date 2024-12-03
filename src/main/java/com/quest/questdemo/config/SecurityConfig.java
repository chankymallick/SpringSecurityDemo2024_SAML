package com.quest.questdemo.config;

import com.quest.questdemo.config.authproviders.CustomDBAuthenticationProvider;
import com.quest.questdemo.config.authproviders.CustomLDAPAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomDBAuthenticationProvider customDBAuthenticationProvider;

    @Autowired
    private CustomLDAPAuthenticationProvider customLDAPAuthenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) throws Exception {
        DefaultRelyingPartyRegistrationResolver relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(
                relyingPartyRegistrationRepository);
        Saml2MetadataFilter filter = new Saml2MetadataFilter(relyingPartyRegistrationResolver, new OpenSamlMetadataResolver());

        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("/LoginPage", "/WEB-INF/views/**").permitAll()
                .anyRequest().authenticated()
                )
                .saml2Login(saml2Login -> saml2Login
                .defaultSuccessUrl("/home", true)
                )
                .saml2Logout(saml2Logout -> saml2Logout
                .logoutUrl("/LoginPage")
                )
                .addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);

        http.authenticationManager(authenticationManager(http.getSharedObject(AuthenticationManagerBuilder.class)))
                .formLogin(formLogin -> formLogin
                .loginPage("/LoginPage")
                .loginProcessingUrl("/login")
                .failureUrl("/LoginPage?error=true")
                .defaultSuccessUrl("/home", true)
                .permitAll()
                )
                .logout(logout -> logout
                .logoutSuccessUrl("/LoginPage")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .permitAll()
                )
                .csrf().disable();
        return http.build();
    }

    public AuthenticationManager authenticationManager(AuthenticationManagerBuilder authenticationManagerBuilder)
            throws Exception {
        authenticationManagerBuilder
                .authenticationProvider(customLDAPAuthenticationProvider) // Add LDAP authentication provider
                .authenticationProvider(customDBAuthenticationProvider); // Add DB authentication provider
        return authenticationManagerBuilder.build();
    }

    @Bean
    public CustomLDAPAuthenticationProvider customLDAPAuthenticationProvider() {
        return new CustomLDAPAuthenticationProvider();
    }

    @Bean
    public CustomDBAuthenticationProvider customAuthenticationProvider() {
        return new CustomDBAuthenticationProvider();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
