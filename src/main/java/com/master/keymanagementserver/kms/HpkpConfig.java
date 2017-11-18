package com.master.keymanagementserver.kms;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;

/**
 * provides the configuration for the http public key pinning
 */
@EnableWebSecurity
public class HpkpConfig extends WebSecurityConfigurerAdapter {
    private static final int MAX_AGE_IN_SECONDS = 60;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers()
                .httpPublicKeyPinning()
                .maxAgeInSeconds(MAX_AGE_IN_SECONDS)
                .addSha256Pins(
                        // own certificate
                        "Tp2zoGRoetwzpZB0fjhDBG4WfQo1Nr5vi0QKt/lGvBs="
                        // https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem
                        , "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg="
                        // https://letsencrypt.org/certs/isrgrootx1.pem
                        , "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M="
                        // Backup-Cert
                        , "juVMdTCelRykDfSbZ1C9KWJhJOMKYDHiI447o2MhWSM="
                )
                .reportOnly(false)
                // .reportUri("http://example.net/hpkp-report")
                .includeSubDomains(true);

        // allow that the KMS can be iframed from the same origin
        http.headers()
                .addHeaderWriter(new XFrameOptionsHeaderWriter(XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN));

        // disable csrf it is not needed due to the lack of form fields
        http.csrf().disable();
    }
}
