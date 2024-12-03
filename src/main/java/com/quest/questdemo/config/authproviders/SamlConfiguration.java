/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.quest.questdemo.config.authproviders;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.stereotype.Component;

/**
 *
 * @author MMallick
 */
@Component
public class SamlConfiguration {

    @Value("classpath:credentials/rp-private.key")
    RSAPrivateKey privateKey;

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
                .fromMetadataLocation("https://dev-26207677.okta.com/app/exklk9bswqBhNMlcH5d7/sso/saml/metadata")
                .registrationId("okta")
                .entityId("http://localhost:8080/questdemo/saml2/service-provider-metadata/okta")
                .decryptionX509Credentials(
                        (c) -> c.add(Saml2X509Credential.decryption(this.privateKey, relyingPartyCertificate())))
                .signingX509Credentials(
                        (c) -> c.add(Saml2X509Credential.signing(this.privateKey, relyingPartyCertificate())))
                .singleLogoutServiceLocation("https://dev-26207677.okta.com")
                .assertionConsumerServiceLocation("http://localhost:8080/questdemo/login/saml2/sso/okta")
                .singleLogoutServiceResponseLocation("http://localhost:8080/logout/saml2/slo")
                .singleLogoutServiceBinding(Saml2MessageBinding.POST).build();

        return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
    }

    X509Certificate relyingPartyCertificate() {
        try (InputStream is = new ClassPathResource("credentials/okta.cert").getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load Okta certificate", ex);
        }
    }

}