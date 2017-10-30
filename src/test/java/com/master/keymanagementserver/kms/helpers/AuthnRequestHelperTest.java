package com.master.keymanagementserver.kms.helpers;

import com.master.keymanagementserver.kms.controllers.AuthnRequestController;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.Assert.assertEquals;

/**
 * AuthnRequestHelper Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Okt 14, 2017</pre>
 */
public class AuthnRequestHelperTest {

    @Mock
    AuthnRequestController authnRequestController;

    AuthnRequestHelper authnRequestHelper;

    @Before
    public void before() throws Exception {
        MockitoAnnotations.initMocks(this);
        authnRequestHelper = new AuthnRequestHelper(authnRequestController);
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: encodeRedirectFormat(String samlXML)
     */
    @Test
    public void testEncodeRedirectFormat() throws Exception {
        String input = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:AuthnRequest " +
                "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
                "AssertionConsumerServiceURL=\"https://neon.cloud.nds.rub.de:443/KMS/ACS\" " +
                "Destination=\"https://service.skidentity.de/fs/saml/remoteauth/\" ForceAuthn=\"false\" " +
                "ID=\"a74072c3-2e44-4c4f-994f-a2ed21867f7f\" IsPassive=\"false\" " +
                "IssueInstant=\"2017-10-14T19:01:19.559Z\" " +
                "ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\">" +
                "<samlp:Issuer xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
                "https://neon.cloud.nds.rub.de:443/KMS</samlp:Issuer><saml2p:NameIDPolicy " +
                "xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" AllowCreate=\"true\" " +
                "Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" SPNameQualifier=\"Issuer\"/>" +
                "<saml2p:RequestedAuthnContext xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
                "Comparison=\"exact\"><saml:AuthnContextClassRef " +
                "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>" +
                "</saml2p:RequestedAuthnContext></samlp:AuthnRequest>";
        String expectedOutput = "vVRbb5swFP4ryO9cS5fGClRZomrR2o0Fuoe9ueawWjM28zFp%2Bu9nIFnzsEbVpO0FIft855zvAovrfSu9" +
                "HRgUWmUkDiLigeK6Fup7Ru6rG%2F%2BKXOcLZK3s6LK3j2oLP3tA6zmcQjpeZKQ3imqGAqliLSC1nJbLu1uaBBHtjLaaa0lOIO" +
                "cRDBGMdQsRb3l8XWmFfQumBLMTHO63txl5tLZDGoYKtAq41H0dqBoD0z8ENdA0vQg%2F3pXhclUSb%2B1WForZkeURh1OvAH%2" +
                "BIGpQV9tnhwgbDYcXQQKstMMc5JN6NNhxG%2FhlpmEQg3madETZLo1nCL%2FwE0tRPedr487l7sATqJL56N2tmjavEwlESO3jB" +
                "IvawUWiZshlJonjmx5Efp1U8p1FM43lweTn%2FRrzioN17oSZHzsn2MBUh%2FVBVhV98LivifT066wrI0cdxunm7gy9%2B5G%2" +
                "BSfBGezpmmJh395Bpv1oWWgj%2BfDE%2F%2BaX6k1E8rA8w68a3pYbSyZfb1DnEQjyei9puxlELLhFzWtQFE4pXFQORLz6RoBJ" +
                "iMTDRJ%2BJvo4ROBegyMS66Fvf1fjFe67ZgROJgOe8btwXZ6usxKOsQWmr8YkJ8t45QPrd3xEPknbeohwsCdGJVhCjtt7BSPP%" +
                "2B6TT3evaZgfk3X6J8p%2FAQ%3D%3D";
        assertEquals("", expectedOutput, authnRequestHelper.encodeRedirectFormat(input));
    }


} 
