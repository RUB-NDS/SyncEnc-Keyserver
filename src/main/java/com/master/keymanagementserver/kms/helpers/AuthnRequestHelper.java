/**
 *
 */
package com.master.keymanagementserver.kms.helpers;

import com.master.keymanagementserver.kms.controllers.AuthnRequestController;
import com.master.keymanagementserver.kms.models.AuthnRequestModel;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.apache.commons.codec.binary.Base64;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

/**
 * provides functions to create the AuthnRequest which needs to be send to the IdP
 */
@Component
public class AuthnRequestHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthnRequestHelper.class);
    // Prefix needed for the Issuer and the AuthnRequest itself
    private static final String NAME_SPACE_PREFIX = "samlp";
    private final AuthnRequestController authnRequestController;
    private String idpURL;
    // the URL of the AuthnRequestIssuer
    private String issuerURL = "http://neon.cloud.nds.rub.de/KMS";
    // the URL of the AuthnRequestConsumer
    private String consumerUrl = "https://neon.cloud.nds.rub.de/KMS/ACS";

    @Autowired
    public AuthnRequestHelper(AuthnRequestController authnRequestController) {
        this.authnRequestController = authnRequestController;
    }

    /**
     * find the SingleSignOnService from MetaData
     *
     * @param idpEntityDescriptor the entityDescriptor from MetaData
     * @return the found SingleSignOnService
     */
    private static SingleSignOnService getSingleSignOnService(EntityDescriptor idpEntityDescriptor) {
        for (SingleSignOnService sss :
                idpEntityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getSingleSignOnServices()) {
            if (sss.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("SingleSignOnService found");
                }
                // if found it can be returned immediately
                return sss;
            }
        }
        return null;
    }

    /**
     * extract the idpURL with the provided HTTPMetadataResolver
     *
     * @param idpMetadataResolver contains the metadata got via HTTP
     * @return the sso service of the idp
     */
    private static SingleSignOnService extractIdpURL(HTTPMetadataResolver idpMetadataResolver) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("extract the idp url from httpMetaData");
        }
        // Iterating through the entries to find the sso service with redirect binding
        for (EntityDescriptor idpEntityDescriptor : idpMetadataResolver) {
            SingleSignOnService sss = getSingleSignOnService(idpEntityDescriptor);
            if (sss != null) {
                return sss;
            }
        }

        return null;
    }

    /**
     * extract the idpURL with the provided FilesystemMetadataResolver
     *
     * @param idpMetadataResolver contains the metadata got via FileSystem
     * @return the sso service of the idp
     */
    private static SingleSignOnService extractIdpURL(FilesystemMetadataResolver idpMetadataResolver) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("extract the idp url from filesystemMetaData");
        }
        // Iterating through the entries to find the sso service with redirect binding
        for (EntityDescriptor idpEntityDescriptor : idpMetadataResolver) {
            SingleSignOnService sss = getSingleSignOnService(idpEntityDescriptor);
            if (sss != null) {
                return sss;
            }
        }

        return null;
    }

    /**
     * generate an issuer with the provided issuer URL
     *
     * @param issuerURL issuer URL the issuer should contain
     * @return the generated Issuer with the provided URL
     */
    private static Issuer getIssuer(String issuerURL) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("build the issuer");
        }
        IssuerBuilder issuerBuilder;
        Issuer issuer;

        issuerBuilder = new IssuerBuilder();
        issuer = issuerBuilder.buildObject(SAMLConstants.SAML20_NS
                , Issuer.DEFAULT_ELEMENT_LOCAL_NAME, NAME_SPACE_PREFIX);
        issuer.setValue(issuerURL);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("issuer: {}", issuer);
            LOGGER.debug("getDOM of Issuer: {}", issuer.getDOM());
        }

        return issuer;
    }

    /**
     * generate the AuthnContextClassRef with an AuthnContextClassRefBuilder
     *
     * @return the generated AuthnContextClassRef
     */
    private static AuthnContextClassRef getRequestedAuthnContextClassRef() {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("build the authnContextClassRef");
        }
        AuthnContextClassRefBuilder authnContextClassRefBuilder;
        AuthnContextClassRef authnContextClassRef;
        String namePrefix = "saml";

        // generate the ContextClassRef with an builder
        authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
        authnContextClassRef = authnContextClassRefBuilder
                .buildObject(SAMLConstants.SAML20_NS, AuthnContextClassRef.DEFAULT_ELEMENT_LOCAL_NAME, namePrefix);
        authnContextClassRef
                .setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

        return authnContextClassRef;
    }

    /**
     * generate the AuthnContext with and AuthnContextBuilder
     *
     * @param authnContextClassRef will be added to the context
     * @return the generated AuthnContext
     */
    private static RequestedAuthnContext getAuthnContext(AuthnContextClassRef authnContextClassRef) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("build the requestedAuthnContext");
        }
        RequestedAuthnContextBuilder requestedAuthnContextBuilder;
        RequestedAuthnContext requestedAuthnContext;

        // generate the AuthnContext with an builder and add the ContextClassRef
        requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
        requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        return requestedAuthnContext;
    }

    /**
     * generate the NameIDPolicy
     *
     * @return the generated NameIDPolicy
     */
    private static NameIDPolicy getNameIDPolicy() {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("build the nameIDPolicy");
        }
        NameIDPolicyBuilder nameIdPolicyBuilder;
        NameIDPolicy nameIdPolicy;

        nameIdPolicyBuilder = new NameIDPolicyBuilder();
        nameIdPolicy = nameIdPolicyBuilder.buildObject();
        // goal is to get the email-address of the user
        nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        nameIdPolicy.setAllowCreate(Boolean.TRUE);

        return nameIdPolicy;
    }

    /**
     * Create a StringWriter out of the provided AuthnRequest
     * the AuthnRequest will be marshalled
     * then an DOMSource will be created
     * and after all it will be transformed to a StringWriter
     *
     * @param authnRequest the authnRequest that should be marshalled an transformed
     * @return the transformed authnRequest
     * @throws MarshallingException   throw exception if authnRequest can not be marshalled
     * @throws TransformerException   throw exception if Transformer can not be instantiated
     *                                or domSource can not be transormed
     * @throws InstantiationException thrown if Marshaller, TransformerFactory or Transformer is null
     */
    private static StringWriter getStringWriter(AuthnRequest authnRequest)
            throws MarshallingException, TransformerException, InstantiationException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("get the String Writer for authnRequest");
        }
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest);

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        if (marshaller == null || transformerFactory == null) {
            throw new InstantiationException();
        }
        Transformer transformer = transformerFactory.newTransformer();
        if (transformer == null) {
            throw new InstantiationException();
        }
        StringWriter stringWriter = new StringWriter();
        StreamResult streamResult = new StreamResult(stringWriter);

        DOMSource domSource = new DOMSource(marshaller.marshall(authnRequest));
        transformer.transform(domSource, streamResult);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("created StringWriter: {}", stringWriter);
        }

        return stringWriter;
    }

    /**
     * encode the provided string so that it can be redirected
     *
     * @param samlXML string that needs to be encoded
     * @return the encoded string
     * @throws IOException thrown if error occured during deflate the string
     */
    String encodeRedirectFormat(String samlXML) throws IOException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("encode the samlXML: {}", LogEncoderHelper.encodeLogEntry(samlXML));
        }
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        samlXML = samlXML.replace("protocol\""
                , "protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"");
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("samlXML after assertion added: {}", samlXML);
        }

        // Deflate the string
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(os, deflater);
        deflaterOutputStream.write(samlXML.getBytes(StandardCharsets.UTF_8));
        deflaterOutputStream.close();
        os.close();
        // encode the string
        String base64 = Base64.encodeBase64String(os.toByteArray());

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("urlEncode the base64 {}", LogEncoderHelper.encodeLogEntry(base64));
        }
        // URLEncode the string, so that "bad" characters are encoded (e.g. "+")
        return URLEncoder.encode(base64, StandardCharsets.UTF_8.name());
    }

    /**
     * load the url of the SSO service
     * and save it in the variable
     *
     * @return false if an error occurred and no url got, true otherwise
     */
    private boolean hasIdpUrlLoaded() {
        try {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("get metadata via http and get idp-url from it");
            }
            // first try to get the metadata via http
            HTTPMetadataResolver idpMetadataResolver = SAMLHelper.getIdpMetaDataViaHTTP();
            SingleSignOnService singleSignOnService = extractIdpURL(idpMetadataResolver);

            if (singleSignOnService == null) {
                LOGGER.error("Found no SingleSignOnService with Redirect Binding with HTTPMetadataResolver.");
                throw new ResolverException();
            }
            idpURL = singleSignOnService.getLocation();

            return true;
        } catch (ResolverException | ComponentInitializationException e) {
            LOGGER.error("Error while trying to get idpMetaData per HTTP. {}", e);
            // if an error occurred while trying to fetch the data via http, try to get via filesystem
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("get metadata via file and get idp-url from it");
            }
            FilesystemMetadataResolver filesystemMetadataResolver = null;
            try {
                filesystemMetadataResolver = SAMLHelper.getIdpMetaDataFromFileSystem();
                SingleSignOnService singleSignOnService = extractIdpURL(filesystemMetadataResolver);
                if (singleSignOnService == null) {
                    LOGGER.error("Found no SingleSignOnService with Redirect Binding with HTTPMetadataResolver.");
                    throw new ResolverException();
                }
                idpURL = singleSignOnService.getLocation();

                return true;
            } catch (ResolverException | ComponentInitializationException e1) {
                // if both lead to an error return false
                LOGGER.error("Error while trying to get idpMetaData from FileSystem. {}", e1);

                return false;
            }
        }
    }

    /**
     * build the authnRequest that needs to be send to the IdP
     * contains Issuer, NameIDPolicy, AuthnContext
     *
     * @return the AuthnRequest
     */
    private AuthnRequest buildAuthnRequestObject(String username) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("build authnRequestObject");
        }
        Issuer issuer;
        NameIDPolicy nameIDPolicy;
        RequestedAuthnContext requestedAuthnContext;
        AuthnContextClassRef authnContextClassRef;

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("get Issuer, NameIDPolicy, authnContextClassRef and requestedAuthnContext");
        }
        // get the individual parts of the AuthnRequest
        issuer = getIssuer(issuerURL);
        nameIDPolicy = getNameIDPolicy();
        authnContextClassRef = getRequestedAuthnContextClassRef();
        requestedAuthnContext = getAuthnContext(authnContextClassRef);

        // pass the individual parts and return the AuthnRequest
        return getAuthnRequest(issuer, nameIDPolicy, requestedAuthnContext, username);
    }

    /**
     * brings together the individual parts which are provided
     *
     * @param issuer                the Issuer the AuthnRequest contains
     * @param nameIDPolicy          the NameIDPolicy the AuthnRequest contains
     * @param requestedAuthnContext the requestedAuthnContext the AuthnRequest contains
     * @return the AuthnRequest with the provided individual parts
     */
    private AuthnRequest getAuthnRequest(Issuer issuer, NameIDPolicy nameIDPolicy
            , RequestedAuthnContext requestedAuthnContext, String username) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("create the authnRequest");
        }
        DateTime issueInstant;
        AuthnRequestBuilder authnRequestBuilder;
        AuthnRequest authnRequest;

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("create the authnRequest in db");
        }
        // create the AuthnRequest in the DB, provides valid range and the ID
        AuthnRequestModel authnRequestModel = authnRequestController
                .createAuthnRequest(username, consumerUrl, issuer.getValue());

        // create the AuthnRequest that is send to the IdP
        authnRequestBuilder = new AuthnRequestBuilder();
        authnRequest = authnRequestBuilder.buildObject(SAMLConstants.SAML20P_NS
                , AuthnRequest.DEFAULT_ELEMENT_LOCAL_NAME, NAME_SPACE_PREFIX);

        authnRequest.setVersion(SAMLVersion.VERSION_20);

        authnRequest.setID(authnRequestModel.getId());

        issueInstant = authnRequestModel.getNotValidBefore();
        authnRequest.setIssueInstant(issueInstant);

        authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);

        authnRequest.setAssertionConsumerServiceURL(consumerUrl);

        authnRequest.setDestination(idpURL);

        authnRequest.setIssuer(issuer);

        authnRequest.setNameIDPolicy(nameIDPolicy);

        authnRequest.setRequestedAuthnContext(requestedAuthnContext);

        return authnRequest;
    }

    /**
     * load the URL of the IdP
     * builds the AuthnRequest
     * encodes the AuthnRequest
     * brings the idpURL, the encoded AuthnRequest and the RelayState together and returns it
     *
     * @return the url to which should be redirected
     */
    public String getRedirectURL(String username) {
        AuthnRequest authnRequest;
        String encodedAuthnRequest;

        try {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("get redirect url");
            }
            if (!hasIdpUrlLoaded()) {
                LOGGER.error("Error while generating RedirectURL. Unable to get the IDP-URL.");
                return "";
            }
            authnRequest = buildAuthnRequestObject(username);
            encodedAuthnRequest = encodeAuthnRequest(authnRequest);

            return idpURL + "?SAMLRequest=" + encodedAuthnRequest + "&RelayState="
                    + authnRequest.getAssertionConsumerServiceURL();
        } catch (TransformerException | MarshallingException | IOException | InstantiationException e) {
            LOGGER.error("Error while generating RedirectURL. Unable to marshall the AuthnRequest. {}", e);

            return "";
        }
    }

    /**
     * encodes the provided authnRequest
     * transform the authnRequest to a string and encode this in redirectForm
     *
     * @param authnRequest authnRequest that needs to be encoded
     * @return the encoded string
     * @throws MarshallingException   throw exception if authnRequest can not be marshalled
     * @throws TransformerException   throw exception if Transformer can not be instantiated
     *                                or domSource can not be transormed
     * @throws IOException            thrown if error occured during deflate the string
     * @throws InstantiationException thrown if Marshaller, TransformerFactory or Transformer is null
     */
    private String encodeAuthnRequest(AuthnRequest authnRequest)
            throws MarshallingException, TransformerException, IOException, InstantiationException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("encode the authnRequest");
        }
        return encodeRedirectFormat(getStringWriter(authnRequest).toString());
    }

}
