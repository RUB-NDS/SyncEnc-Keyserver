package com.master.keymanagementserver.kms.helpers;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class SAMLHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(SAMLHelper.class);

    public SAMLHelper() {
    }

    /**
     * get the metadata via HTTP
     *
     * @return the metadata resolver which was got
     * @throws ResolverException                throw exception if metadata can not be resolved for the idpMetaDataURL
     * @throws ComponentInitializationException throw exception if BasicParserPool or Resolver could not be initialized
     */
    static HTTPMetadataResolver getIdpMetaDataViaHTTP()
            throws ResolverException, ComponentInitializationException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("try to get the MetaData via HTTP");
        }
        // the URL where the metadata should lie
        String idpMetaDataURL = "https://service.skidentity.de/fs/saml/metadata";

        // create an httpCLient to get the metadata via http
        HttpClient httpClient = HttpClientBuilder.create().build();
        HTTPMetadataResolver idpMetadataResolver = new HTTPMetadataResolver(httpClient, idpMetaDataURL);
        // providing no id will lead to an error
        idpMetadataResolver.setId("idpMetaDataResolverID");
        idpMetadataResolver.setRequireValidMetadata(true);

        // create an parser pool and add it to the resolver
        BasicParserPool basicParserPool = new BasicParserPool();
        basicParserPool.initialize();
        idpMetadataResolver.setParserPool(basicParserPool);
        idpMetadataResolver.initialize();

        return idpMetadataResolver;
    }

    /**
     * get the metadata via filesystem
     *
     * @return the metadata resolver which was got
     * @throws ResolverException                throw exception if metadata can not be resolved for the idpMetaDataURL
     * @throws ComponentInitializationException throw exception if BasicParserPool or Resolver could not be initialized
     */
    static FilesystemMetadataResolver getIdpMetaDataFromFileSystem()
            throws ResolverException, ComponentInitializationException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("try to get the MetaData via File");
        }
        String pathToFile = "./libs/.skidentityCC/SkIDentity_metadata.xml";
        FilesystemMetadataResolver filesystemMetadataResolver = new FilesystemMetadataResolver(new File(pathToFile));
        filesystemMetadataResolver.setRequireValidMetadata(true);
        // providing no id will lead to an error
        filesystemMetadataResolver.setId("idpMetaDataResolverID");

        // create an parser pool and add it to the resolver
        BasicParserPool basicParserPool = new BasicParserPool();
        basicParserPool.initialize();
        filesystemMetadataResolver.setParserPool(basicParserPool);
        filesystemMetadataResolver.initialize();

        return filesystemMetadataResolver;
    }


}
