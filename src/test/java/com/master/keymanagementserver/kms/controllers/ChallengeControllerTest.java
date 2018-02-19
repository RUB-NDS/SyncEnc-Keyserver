package com.master.keymanagementserver.kms.controllers;

import com.master.keymanagementserver.kms.crypto.CryptoUtils;
import com.master.keymanagementserver.kms.crypto.Randomness;
import com.master.keymanagementserver.kms.models.ChallengeModel;
import com.master.keymanagementserver.kms.models.UserModel;
import com.master.keymanagementserver.kms.repositories.ChallengeRepository;
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
 * ChallengeController Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Oct 10, 2017</pre>
 */
public class ChallengeControllerTest {

    @Mock
    ChallengeRepository challengeRepository;
    @Mock
    private Randomness randomness;
    @Mock
    private CryptoUtils cryptoUtils;

    private ChallengeController challengeController;
    private UserModel userModel;
    private ChallengeModel challengeModel;

    @Before
    public void before() throws Exception {
        MockitoAnnotations.initMocks(this);
        userModel = new UserModel("pg@rub.de", "identifier");
        challengeController = new ChallengeController(challengeRepository, randomness, cryptoUtils);
        challengeModel = new ChallengeModel("chall", userModel);
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: searchChallengeForUser(UserModel userModel)
     */
    @Test
    public void testSearchChallengeForUser() throws Exception {
        Mockito.when(challengeRepository.findChallengeByUserModel(userModel)).thenReturn(challengeModel);

        assertEquals("", challengeModel, challengeController.searchChallengeForUser(userModel));
    }

    /**
     * Method: searchChallengeForUser(UserModel userModel)
     */
    @Test
    public void testSearchChallengeForUserNonExistingUser() throws Exception {
        assertNull("", challengeController.searchChallengeForUser(userModel));
    }

    /**
     * Method: getChallengeForUser(UserModel userModel)
     */
    @Test
    public void testGetChallengeForUserExistingChallenge() throws Exception {
        Mockito.when(challengeController.searchChallengeForUser(userModel)).thenReturn(challengeModel);

        assertEquals("", challengeModel.getChallenge(), challengeController.getChallengeForUser(userModel));
    }

    /**
     * Method: getChallengeForUser(UserModel userModel)
     */
    @Test
    public void testGetChallengeForUserCreateChallenge() throws Exception {
        String created = challengeController.getChallengeForUser(userModel);

        assertNotNull("", created);
    }

    /**
     * Method: deleteOldChallenges(Date now)
     */
    @Test
    public void testDeleteOldChallenges() throws Exception {
        ChallengeModel fastInvalid = new ChallengeModel("chall", userModel, 5);
        ChallengeModel[] array = {fastInvalid};
        Iterable<ChallengeModel> iterable = Arrays.asList(array);
        Date input = DateTime.now().minusSeconds(5).toDate();
        Mockito.when(challengeRepository.findChallengesByNotValidAfterIsBefore(input)).thenReturn(iterable);

        assertTrue("", challengeController.deleteOldChallenges(input));
    }


    /**
     * Method: createChallengeForUser(UserModel userModel)
     */
    @Test
    public void testCreateChallengeForUserNullAsUser() throws Exception {
        assertNull("", challengeController.createChallengeForUser(null));
    }

    /**
     * Method: createChallengeForUser(UserModel userModel)
     */
    @Test
    public void testCreateChallengeForUserExistingUser() throws Exception {
        Mockito.when(challengeRepository.save(any(ChallengeModel.class))).thenThrow(new DataIntegrityViolationException("Challenge already exists"));

        assertNull("", challengeController.createChallengeForUser(userModel));
    }

    /**
     * Method: createChallengeForUser(UserModel userModel)
     */
    @Test
    public void testCreateChallengeForUser() throws Exception {
        assertNotNull("", challengeController.createChallengeForUser(userModel));
    }

}
