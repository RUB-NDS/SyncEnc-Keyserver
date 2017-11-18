package com.master.keymanagementserver.kms.controllers;

import com.master.keymanagementserver.kms.models.AuthnRequestModel;
import com.master.keymanagementserver.kms.repositories.AuthnRequestRepository;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.Arrays;
import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;

/**
 * AuthnRequestController Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Oct 10, 2017</pre>
 */
public class AuthnRequestControllerTest {
    @Rule
    public final ExpectedException exception = ExpectedException.none();
    @Mock
    private AuthnRequestRepository authnRequestRepository;
    private AuthnRequestController authnRequestController;

    @Before
    public void before() throws Exception {
        MockitoAnnotations.initMocks(this);
        authnRequestController = new AuthnRequestController(authnRequestRepository);
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: createAuthnRequest(String relayState, String issuer)
     */
    @Test
    public void testCreateAuthnRequest() throws Exception {
        AuthnRequestModel created = authnRequestController.createAuthnRequest("username", "relay", "issuer");

        assertEquals("", "relay", created.getRelayState());
        assertEquals("", "issuer", created.getIssuer());
    }

    /**
     * Method: createAuthnRequest(String relayState, String issuer)
     */
    @Test
    public void testCreateAuthnRequestExistingRequest() throws Exception {
        Mockito.when(authnRequestRepository.save(any(AuthnRequestModel.class))).thenThrow(new DataIntegrityViolationException("AuthnRequest already exists."));
        AuthnRequestModel created = authnRequestController.createAuthnRequest("username", "relay", "issuer");

        assertNull("", created);
    }

    /**
     * Method: deleteAllOldAuthnRequest(Date now)
     */
    @Test
    public void testDeleteAllOldAuthnRequest() throws Exception {
        AuthnRequestModel fastInvalid = new AuthnRequestModel("username", "relay", "issuer", 5);
        AuthnRequestModel[] array = {fastInvalid};
        Iterable<AuthnRequestModel> iterable = Arrays.asList(array);
        Date input = DateTime.now().minusSeconds(5).toDate();
        Mockito.when(authnRequestRepository.findAuthnRequestsByNotValidAfterIsBefore(input)).thenReturn(iterable);

        assertTrue("", authnRequestController.deleteAllOldAuthnRequest(input));
    }

    /**
     * Method: deleteAllOldAuthnRequest(Date now)
     */
    @Test
    public void testDeleteAllOldAuthnRequesExceptiont() throws Exception {
        Date input = DateTime.now().toDate();
        exception.expect(NullPointerException.class);
        authnRequestController.deleteAllOldAuthnRequest(input);
    }


} 
