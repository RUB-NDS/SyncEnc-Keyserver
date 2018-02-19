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
    AuthnRequestModel authnRequestModel;

    @Before
    public void before() throws Exception {
        MockitoAnnotations.initMocks(this);
        authnResponseHelper = new AuthnResponseHelper(authnRequestRepository, timeHelper);
        authnRequestModel = new AuthnRequestModel("username", "relaysState", "issuer");
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: checkIssuerOfAuthnResponse(Issuer issuerAuthnResponse, AuthnRequestModel authnRequestModel)
     */
    @Test
    public void testCheckIssuerOfAuthnResponse() throws Exception {
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject(SAMLConstants.SAML20_NS, "Issuer", "samlp");
        issuer.setValue("issuer");

        assertTrue("", authnResponseHelper.checkIssuerOfAuthnResponse(issuer.getValue(), authnRequestModel));

        issuerBuilder = new IssuerBuilder();
        issuer = issuerBuilder.buildObject(SAMLConstants.SAML20_NS, "Issuer", "samlp");
        issuer.setValue("issuerFalse");

        assertFalse("", authnResponseHelper.checkIssuerOfAuthnResponse(issuer.getValue(), authnRequestModel));
    }

    /**
     * Method: getRelatedAuthnRequest(String inResponseTo)
     */
    @Test
    public void testGetRelatedAuthnRequest() throws Exception {
        Mockito.when(authnRequestRepository.findAuthnRequestById(authnRequestModel.getId())).thenReturn(authnRequestModel);

        AuthnRequestModel found = authnResponseHelper.getRelatedAuthnRequest(authnRequestModel.getId());

        assertEquals("", authnRequestModel, found);
    }

    @Test
    public void testParseAuthnResponse() throws Exception {
        String samlResponse = "";
        String relayState = "relayState";
        assertEquals("", "patrick.geisler-a85@rub.de", authnResponseHelper.parseAuthnResponse(samlResponse, relayState));
    }

} 
