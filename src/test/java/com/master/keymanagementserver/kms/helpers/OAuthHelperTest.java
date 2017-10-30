package com.master.keymanagementserver.kms.helpers;

import com.master.keymanagementserver.kms.controllers.OAuthController;
import com.master.keymanagementserver.kms.models.OAuthModel;
import com.master.keymanagementserver.kms.models.UserModel;
import com.master.keymanagementserver.kms.repositories.OAuthRepository;
import org.hamcrest.Matchers;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;

/**
 * OAuthHelper Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Oct 10, 2017</pre>
 */
public class OAuthHelperTest {
    @Mock
    private OAuthRepository oAuthRepository;
    @Mock
    private TimeHelper timeHelper;

    private OAuthController oAuthController;
    private OAuthHelper oAuthHelper;
    private OAuthModel oAuthModel;

    @Before
    public void before() throws Exception {
        MockitoAnnotations.initMocks(this);
        oAuthController = new OAuthController(oAuthRepository);
        oAuthHelper = new OAuthHelper(oAuthController, timeHelper);
        UserModel userModel = new UserModel("pg@rub.de");
        oAuthModel = new OAuthModel("access", userModel);
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: getOAuthTokenbyAuthHeader(String authorization)
     */
    @Test
    public void testGetOAuthTokenNullToken() throws Exception {
        assertNull("", oAuthHelper.getOAuthTokenbyAuthHeader(null));
    }

    /**
     * Method: getOAuthTokenbyAuthHeader(String authorization)
     */
    @Test
    public void testGetOAuthTokenEmptyToken() throws Exception {
        assertNull("", oAuthHelper.getOAuthTokenbyAuthHeader(""));
    }

    /**
     * Method: getOAuthTokenbyAuthHeader(String authorization)
     */
    @Test
    public void testGetOAuthTokenNoBeaer() throws Exception {
        assertNull("", oAuthHelper.getOAuthTokenbyAuthHeader("access token"));
    }

    /**
     * Method: getOAuthTokenbyAuthHeader(String authorization)
     */
    @Test
    public void testGetOAuthTokenNoToken() throws Exception {
        assertNull("", oAuthHelper.getOAuthTokenbyAuthHeader("bearer"));
    }

    /**
     * Method: getOAuthTokenbyAuthHeader(String authorization)
     */
    @Test
    public void testGetOAuthToken() throws Exception {
        Mockito.when(oAuthController.getOAuthTokenByTokenId(oAuthModel.getTokenId())).thenReturn(oAuthModel);
        Mockito.when(timeHelper.checkTimeValidity(any(DateTime.class), any(OAuthModel.class))).thenReturn(true);

        assertEquals("", oAuthModel, oAuthHelper.getOAuthTokenbyAuthHeader("bearer " + oAuthModel.getTokenId()));
    }

    /**
     * Method: getOAuthTokenbyAuthHeader(String authorization)
     */
    @Test
    public void testGetOAuthTokenNonExisting() throws Exception {
        assertNull("", oAuthHelper.getOAuthTokenbyAuthHeader("bearer abc"));
    }

    /**
     * Method: getOAuthTokenbyAuthHeader(String authorization)
     */
    @Test
    public void testGetOAuthTokenNotValid() throws Exception {
        Mockito.when(oAuthController.getOAuthTokenByTokenId(oAuthModel.getTokenId())).thenReturn(oAuthModel);
        Mockito.when(timeHelper.checkTimeValidity(new DateTime(), oAuthModel)).thenReturn(Boolean.FALSE);

        assertNull("", oAuthHelper.getOAuthTokenbyAuthHeader("bearer " + oAuthModel.getTokenId()));
    }

    /**
     * Method: checkOAuthReturnErrorString(OAuthModel oAuthModel, String expectedString)
     */
    @Test
    public void testCheckOAuthReturnErrorStringWrongState() throws Exception {
        assertThat("", oAuthHelper.checkOAuthReturnErrorString(oAuthModel, "SOLVECHALL"), Matchers.containsString("{\"error\":\"SOLVECHALL is not next step\", \"todo\":\"SENDPUBKEY\"}"));
    }

    /**
     * Method: checkOAuthReturnErrorString(OAuthModel oAuthModel, String expectedString)
     */
    @Test
    public void testCheckOAuthReturnErrorStringNullToken() throws Exception {
        assertEquals("", "{\"error\":\"no OAuth Token found.\", \"todo\":\"send request with correct OAuthToken\"}", oAuthHelper.checkOAuthReturnErrorString(null, "SENDPUBKEY"));
    }

    /**
     * Method: checkOAuthReturnErrorString(OAuthModel oAuthModel, String expectedString)
     */
    @Test
    public void testCheckOAuthReturnErrorString() throws Exception {
        assertEquals("", "", oAuthHelper.checkOAuthReturnErrorString(oAuthModel, "SENDPUBKEY"));
    }


} 
