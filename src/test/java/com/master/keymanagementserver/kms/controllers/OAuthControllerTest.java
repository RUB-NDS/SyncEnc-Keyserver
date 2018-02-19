package com.master.keymanagementserver.kms.controllers;

import com.master.keymanagementserver.kms.models.OAuthModel;
import com.master.keymanagementserver.kms.models.UserModel;
import com.master.keymanagementserver.kms.repositories.OAuthRepository;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.Arrays;
import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;

/**
 * OAuthController Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Oct 10, 2017</pre>
 */
public class OAuthControllerTest {
    @Mock
    private OAuthRepository oAuthRepository;
    @Mock
    private OAuthController oAuthController;
    private OAuthModel oAuthModel;
    private UserModel userModel;

    @Before
    public void before() throws Exception {
        MockitoAnnotations.initMocks(this);
        userModel = new UserModel("pg@rub.de", "identifier");
        oAuthController = new OAuthController(oAuthRepository);
        oAuthModel = new OAuthModel("access", userModel);
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: getOAuthTokenByTokenId(String oAuthTokenId)
     */
    @Test
    public void testGetOAuthTokenByTokenId() throws Exception {
        Mockito.when(oAuthRepository.findOAuthModelByTokenId(oAuthModel.getTokenId())).thenReturn(oAuthModel);

        assertEquals("", oAuthModel, oAuthController.getOAuthTokenByTokenId(oAuthModel.getTokenId()));
    }

    /**
     * Method: getOAuthTokenByTokenId(String oAuthTokenId)
     */
    @Test
    public void testGetOAuthTokenByTokenIdNonExistingToken() throws Exception {
        Mockito.when(oAuthRepository.findOAuthModelByTokenId(oAuthModel.getTokenId())).thenReturn(null);

        assertNull("", oAuthController.getOAuthTokenByTokenId(oAuthModel.getTokenId()));
    }

    /**
     * Method: getOAuthTokenByTokenId(String oAuthTokenId)
     */
    @Test
    public void testGetOAuthTokenByTokenIdNonExistingTokenException() throws Exception {
        Mockito.when(oAuthRepository.findOAuthModelByTokenId(oAuthModel.getTokenId())).thenThrow(new NullPointerException("Token with given ID does not exist."));

        assertNull("", oAuthController.getOAuthTokenByTokenId(oAuthModel.getTokenId()));
    }

    /**
     * Method: getOAuthTokenByTokenId(String oAuthTokenId)
     */
    @Test
    public void testGetOAuthTokenByTokenIdEmptyTokenId() throws Exception {
        Mockito.when(oAuthRepository.findOAuthModelByTokenId(oAuthModel.getTokenId())).thenReturn(oAuthModel);

        assertNull("", oAuthController.getOAuthTokenByTokenId(""));
    }

    /**
     * Method: getOAuthTokenbyAuthHeader(UserModel userModel)
     */
    @Test
    public void testGetOAuthToken() throws Exception {
        Mockito.when(oAuthController.searchOAuthModel(userModel)).thenReturn(oAuthModel);

        assertEquals("", oAuthModel, oAuthController.getOAuthToken(userModel));
    }

    /**
     * Method: getOAuthTokenbyAuthHeader(UserModel userModel)
     */
    @Test
    public void testGetOAuthTokenUserModelNull() throws Exception {
        assertNull("", oAuthController.getOAuthToken(null));
    }

    /**
     * Method: deleteOldTokens(Date now)
     */
    @Test
    public void testDeleteOldTokens() throws Exception {
        OAuthModel fastInvalid = new OAuthModel("token", userModel, 5);
        OAuthModel[] array = {fastInvalid};
        Iterable<OAuthModel> iterable = Arrays.asList(array);
        Date input = DateTime.now().minusSeconds(5).toDate();
        Mockito.when(oAuthRepository.findOAuthModelsByNotValidAfterIsBefore(input)).thenReturn(iterable);

        assertTrue("", oAuthController.deleteOldTokens(input));
    }


    /**
     * Method: createOAuthTokenForUser(UserModel userModel, String tokenType)
     */
    @Test
    public void testCreateOAuthTokenForUser() throws Exception {
        assertNotNull("", oAuthController.createOAuthTokenForUser(userModel, "access"));
    }

    /**
     * Method: createOAuthTokenForUser(UserModel userModel, String tokenType)
     */
    @Test
    public void testCreateOAuthTokenForUserUserModelNull() throws Exception {
        assertNull("", oAuthController.createOAuthTokenForUser(null, "access"));
    }

    /**
     * Method: createOAuthTokenForUser(UserModel userModel, String tokenType)
     */
    @Test
    public void testCreateOAuthTokenForUserExistingToken() throws Exception {
        Mockito.when(oAuthRepository.save(any(OAuthModel.class))).thenThrow(new DataIntegrityViolationException("token already exists"));

        assertNull("", oAuthController.createOAuthTokenForUser(null, "access"));
    }

    /**
     * Method: searchOAuthModel(UserModel userModel)
     */
    @Test
    public void testSearchOAuthModel() throws Exception {
        Mockito.when(oAuthRepository.findOAuthModelByUserModel(userModel)).thenReturn(oAuthModel);

        assertEquals("", oAuthModel, oAuthController.searchOAuthModel(userModel));
    }

    /**
     * Method: searchOAuthModel(UserModel userModel)
     */
    @Test
    public void testSearchOAuthModelUserModelNull() throws Exception {
        assertNull("", oAuthController.searchOAuthModel(null));
    }

    /**
     * Method: searchOAuthModel(UserModel userModel)
     */
    @Test
    public void testSearchOAuthModelNoneExistingOAuthModel() throws Exception {
        Mockito.when(oAuthRepository.findOAuthModelByUserModel(any(UserModel.class))).thenThrow(new NullPointerException("no token for User exists."));

        assertNull("", oAuthController.searchOAuthModel(userModel));
    }

}
