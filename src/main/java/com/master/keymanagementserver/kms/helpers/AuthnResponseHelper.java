package com.master.keymanagementserver.kms.helpers;

import com.amazonaws.util.StringInputStream;
import com.master.keymanagementserver.kms.models.AuthnRequestModel;
import com.master.keymanagementserver.kms.repositories.AuthnRequestRepository;
import com.nimbusds.jose.util.Base64;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.joda.time.DateTime;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;

/**
 * provides functions to parse the SAMLResponse provided by the IdP
 */
@Component
public class AuthnResponseHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthnResponseHelper.class);

    private final AuthnRequestRepository authnRequestRepository;
    private final TimeHelper timeHelper;

    @Autowired
    public AuthnResponseHelper(AuthnRequestRepository authnRequestRepository, TimeHelper timeHelper) {
        this.authnRequestRepository = authnRequestRepository;
        this.timeHelper = timeHelper;
    }

    /**
     * parses the SAMLResponse provided by the IdP
     *
     * @param httpServletRequest the request that provides the SAMLResponse
     * @return the email provided in the Response, empty String in case of an error
     */
    public String parseAuthnResponse(HttpServletRequest httpServletRequest) {
        try {
            // Get the SAMLResponse which is provided by the IdP
            String samlResponse = httpServletRequest.getParameter("SAMLResponse");
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("respMessage: {}"
                        , LogEncoderHelper.encodeLogEntry(samlResponse));
            }

            if (samlResponse == null || "".equals(samlResponse)) {
                return null;
            }

            byte[] decode = ConversionHelper.base64DecodeToBytes(new Base64(samlResponse));
            String decodedSAMLstr = new String(decode, "UTF-8");
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("decoded: {}"
                        , LogEncoderHelper.encodeLogEntry(decodedSAMLstr));
            }

            Response response = (Response) XMLObjectSupport.unmarshallFromInputStream(
                    XMLObjectProviderRegistrySupport.getParserPool(), new StringInputStream(decodedSAMLstr));
            AuthnRequestModel authnRequestModel = getRelatedAuthnRequest(response.getInResponseTo());
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("id of found AuthnRequest: {}"
                        , LogEncoderHelper.encodeLogEntry(authnRequestModel.getId()));
            }

        /*
            Check if an AuthnRequest was found in the db
            Check if the SAMLResponse and the AuthnRequest are in the valid range
            Check if the RelayState is the same which was send to the IdP
         */
            DateTime issueInstant = response.getIssueInstant();
            if (authnRequestModel == null
                    || !timeHelper.checkTimeValidity(issueInstant, authnRequestModel)
                    || !httpServletRequest.getParameter("RelayState").equals(authnRequestModel.getRelayState())) {
                // return an empty string if on of the conditions does not fulfill
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("is Null: {}"
                            , authnRequestModel == null);
                    LOGGER.debug("equals: {}"
                            , httpServletRequest.getParameter("RelayState")
                                    .equals(authnRequestModel.getRelayState()));
                    LOGGER.debug("stored RelayState: {}"
                            , LogEncoderHelper.encodeLogEntry(authnRequestModel.getRelayState()));
                    LOGGER.debug("gotten RelayState: {}"
                            , LogEncoderHelper.encodeLogEntry(httpServletRequest.getParameter("RelayState")));
                }
                LOGGER.error("Assertion does not belong to an active/valid AuthnRequest.");

                return null;
            }

            if (response.getAssertions().isEmpty()) {
                LOGGER.error("no Assertion was send. Maybe User has not logged in.");

                return null;
            }
            // get the Assertion out of the SAMLResponse and check if the issuer is correct
            Assertion assertion = response.getAssertions().get(0);
            if (!checkIssuerOfAuthnResponse(assertion.getIssuer(), authnRequestModel)) {
                LOGGER.error("Issuer from Assertion not match the stored Issuer!");

                return null;
            }

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("verify the Signature");
            }
            if (!isAssertionVerifiable(assertion)) {
                LOGGER.error("signature could not be verified");

                return null;
            }

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("find the mail from the attribute");
            }
            // search for the attributeStatement mail in the assertion
            for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
                for (Attribute attribute : attributeStatement.getAttributes()) {
                    if ("mail".equals(attribute.getName().trim())) {
                        return attribute.getAttributeValues().get(0).getDOM().getFirstChild().getNodeValue();
                    }
                }
            }

            return "babo@mail.com";
        } catch (IOException | UnmarshallingException | XMLParserException e) {
            LOGGER.error("Error occured while parsing the SAMLResponse", e);

            return null;
        }
    }

    private boolean isAssertionVerifiable(Assertion assertion) {
        try {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("verify the assertion");
            }
            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(new EntityIdCriterion("https://service.skidentity.de/fs/saml/metadata"));
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("get the certificate from metadata");
            }
            org.opensaml.xmlsec.signature.X509Certificate openSamlCert = SAMLHelper
                    .getIdpMetaDataFromFileSystem()
                    .resolveSingle(criteriaSet)
                    .getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol")
                    .getKeyDescriptors().get(0)
                    .getKeyInfo()
                    .getX509Datas().get(0)
                    .getX509Certificates().get(0);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("{}"
                        , LogEncoderHelper.encodeLogEntry(openSamlCert.getValue()));
            }
            InputStream inputStream = new ByteArrayInputStream(ConversionHelper
                    .base64DecodeToBytes(new Base64(openSamlCert.getValue())));
            X509Certificate x509Certificate = (X509Certificate) CertificateFactory.getInstance("X509")
                    .generateCertificate(inputStream);
            Credential credential = CredentialSupport.getSimpleCredential(x509Certificate, null);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("validate with profileValidator and signatureValidator");
            }
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(assertion.getSignature());
            SignatureValidator.validate(assertion.getSignature(), credential);

            return true;
        } catch (CertificateException | SignatureException | ResolverException | ComponentInitializationException e) {
            // ig the Signature is not valid the SignatureException is thrown
            LOGGER.error("Error verifying the signature of the assertion. ", e);

            return false;
        }
    }

    /**
     * check if the issuer stored in the db and the issuer provided in the Assertion are equal
     *
     * @param issuerAuthnResponse the issuer provided by the Asssertion
     * @param authnRequestModel   AuthnRequest stored in the database
     * @return true if both are equal, false otherwise
     */

    boolean checkIssuerOfAuthnResponse(Issuer issuerAuthnResponse, AuthnRequestModel authnRequestModel) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("check the issuer of response {} and stored one {}"
                    , LogEncoderHelper.encodeLogEntry(issuerAuthnResponse.getValue())
                    , LogEncoderHelper.encodeLogEntry(authnRequestModel.getIssuer()));
        }
        String issuerAuthnRequest = authnRequestModel.getIssuer();

        return issuerAuthnRequest.equals(issuerAuthnResponse.getValue());
    }

    /**
     * query the related AuthnRequest from the database to the inResponseTo-String provided by the Assertion
     *
     * @param inResponseTo the id of the AuthnRequest provided by he Assertion
     * @return the AuthnRequestModel which has the same id, null if none was found
     */
    AuthnRequestModel getRelatedAuthnRequest(String inResponseTo) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("get the related AuthnRequest for {}"
                    , LogEncoderHelper.encodeLogEntry(inResponseTo));
        }
        try {
            return authnRequestRepository.findAuthnRequestById(inResponseTo);
        } catch (NullPointerException e) {
            LOGGER.error("There exists no AuthnRequest with the id {}", inResponseTo);
            LOGGER.error("NullPointerException:", e);

            return null;
        }
    }

}
