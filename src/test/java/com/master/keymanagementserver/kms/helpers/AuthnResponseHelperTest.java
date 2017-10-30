package com.master.keymanagementserver.kms.helpers;

import com.master.keymanagementserver.kms.models.AuthnRequestModel;
import com.master.keymanagementserver.kms.repositories.AuthnRequestRepository;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * AuthnResponseHelper Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Oct 14, 2017</pre>
 */
public class AuthnResponseHelperTest {

    @Mock
    AuthnRequestRepository authnRequestRepository;
    @Mock
    TimeHelper timeHelper;

    AuthnResponseHelper authnResponseHelper;

    @Before
    public void before() throws Exception {
        MockitoAnnotations.initMocks(this);
        authnResponseHelper = new AuthnResponseHelper(authnRequestRepository, timeHelper);
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: checkIssuerOfAuthnResponse(Issuer issuerAuthnResponse, AuthnRequestModel authnRequestModel)
     */
    @Test
    public void testCheckIssuerOfAuthnResponse() throws Exception {
        AuthnRequestModel authnRequestModel = new AuthnRequestModel("relaysState", "issuer");

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject(SAMLConstants.SAML20_NS, "Issuer", "samlp");
        issuer.setValue("issuer");

        assertTrue("", authnResponseHelper.checkIssuerOfAuthnResponse(issuer, authnRequestModel));

        issuerBuilder = new IssuerBuilder();
        issuer = issuerBuilder.buildObject(SAMLConstants.SAML20_NS, "Issuer", "samlp");
        issuer.setValue("issuerFalse");

        assertFalse("", authnResponseHelper.checkIssuerOfAuthnResponse(issuer, authnRequestModel));
    }

    /**
     * Method: getRelatedAuthnRequest(String inResponseTo)
     */
    @Test
    public void testGetRelatedAuthnRequest() throws Exception {
        AuthnRequestModel authnRequestModel = new AuthnRequestModel("relay", "issuer");
        Mockito.when(authnRequestRepository.findAuthnRequestById(authnRequestModel.getId())).thenReturn(authnRequestModel);

        AuthnRequestModel found = authnResponseHelper.getRelatedAuthnRequest(authnRequestModel.getId());

        assertEquals("", authnRequestModel, found);
    }

} 
