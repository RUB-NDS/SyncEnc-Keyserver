/*
 *
 * Title:            Entwicklung eines Schlüsselmanagement-Servers für Cloud Dienste
 * Submission date:  13.11.2017
 *
 * Author:           Patrick Geisler
 * Email:            Patrick.Geisler-a85@rub.de
 * Lecturer's Name:  Prof. Dr. Jörg Schwenk <joerg.schwenk@rub.de>
 *                   Dennis Felsch          <dennis.felsch@ruhr-uni-bochum.de>
 *                   Paul Christoph Rösler  <Paul.Roesler@ruhr-uni-bochum.de>
 *
 * As part of my masterthesis this key management sever was developed.
 *
 */
package com.master.keymanagementserver.kms;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.EmbeddedServletContainerFactory;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.annotation.Bean;

/**
 * standard Configuration class
 * configures the redirect and starts the application
 */
@SpringBootApplication()
public class KmsApplication {
    // http und https port
    @Value("${server.port.http}")
    private int serverPortHttp;
    @Value("${server.port}")
    private int serverPortHttps;

    // run the application
    public static void main(String[] args) {
        SpringApplication.run(KmsApplication.class, args);
    }

    /**
     * Bean used for redirecting from http port to https
     *
     * @return
     */
    @Bean
    public EmbeddedServletContainerFactory servletContainer() {
        TomcatEmbeddedServletContainerFactory tomcat =
                new TomcatEmbeddedServletContainerFactory() {

                    @Override
                    protected void postProcessContext(Context context) {
                        SecurityConstraint securityConstraint = new SecurityConstraint();
                        securityConstraint.setUserConstraint("NONE");
                        SecurityCollection collection = new SecurityCollection();
                        collection.addPattern("/.well-known/*");
                        securityConstraint.addCollection(collection);
                        context.addConstraint(securityConstraint);

                        securityConstraint = new SecurityConstraint();
                        securityConstraint.setUserConstraint("CONFIDENTIAL");
                        collection = new SecurityCollection();
                        collection.addPattern("/*");
                        securityConstraint.addCollection(collection);
                        context.addConstraint(securityConstraint);
                    }
                };
        tomcat.addAdditionalTomcatConnectors(createHttpConnector());
        return tomcat;
    }

    /**
     * used for redirecting from http port to https
     *
     * @return the connector for the redirecting
     */
    private Connector createHttpConnector() {
        Connector connector =
                new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setScheme("http");
        connector.setSecure(false);
        connector.setPort(serverPortHttp);
        connector.setRedirectPort(serverPortHttps);
        return connector;
    }
}
