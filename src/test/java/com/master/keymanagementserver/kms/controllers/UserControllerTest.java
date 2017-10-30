package com.master.keymanagementserver.kms.controllers;

import com.master.keymanagementserver.kms.crypto.CryptoUtils;
import com.master.keymanagementserver.kms.crypto.Randomness;
import com.master.keymanagementserver.kms.helpers.UserStates;
import com.master.keymanagementserver.kms.models.ChallengeModel;
import com.master.keymanagementserver.kms.models.UserModel;
import com.master.keymanagementserver.kms.repositories.UserRepository;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.dao.DataIntegrityViolationException;

import java.lang.reflect.Method;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;

/**
 * UserController Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Okt 9, 2017</pre>
 */
public class UserControllerTest {

    @Rule
    public final ExpectedException exception = ExpectedException.none();
    @Mock
    private UserRepository userRepository;
    @Mock
    private ChallengeController challengeController;
    @Mock
    private Randomness randomness;
    @Mock
    private CryptoUtils cryptoUtils;
    private UserModel userModel;
    private UserModel userModel2;
    private UserController userController;
    private String pubKey = "pubKey";
    private String emailPG = "pg@rub.de";
    private String emailPGE = "pge@rub.de";
    private String emailPG1 = "pg1@rub.de";

    @Before
    public void before() throws Exception {
        MockitoAnnotations.initMocks(this);
        userModel = new UserModel(emailPG);
        userModel2 = new UserModel(emailPGE);
        userController = new UserController(userRepository, challengeController, randomness, cryptoUtils);
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: addPublicKey(String email, String pubKey)
     */
    @Test
    public void testAddPublicKeyNonExistingUser() throws Exception {
        assertNull("", userController.addPublicKey(emailPG1, pubKey));
    }

    /**
     * Method: addPublicKey(String email, String pubKey)
     */
    @Test
    public void testAddPublicKeyExistingKeyNameId() throws Exception {
        Mockito.when(userController.searchUser(emailPG)).thenReturn(userModel);
        Mockito.when(userRepository.save(userModel)).thenThrow(new DataIntegrityViolationException("keyNameId already exists"));

        assertNull("", userController.addPublicKey(emailPG, pubKey));
    }

    /**
     * Method: addPublicKey(String email, String pubKey)
     */
    @Test
    public void testAddPublicKey() throws Exception {
        Mockito.when(userController.searchUser(emailPG)).thenReturn(userModel);
        Mockito.when(userRepository.save(userModel)).thenReturn(userModel);

        assertEquals("", pubKey, userController.addPublicKey(emailPG, pubKey).getPublicKey());
    }

    /**
     * Method: checkChallenge(UserModel userModel, String solvedChallenge)
     */
    @Test
    public void testCheckChallenge() throws Exception {
        ChallengeModel challengeModel = new ChallengeModel("challenge", userModel);
        Mockito.when(challengeController.searchChallengeForUser(userModel)).thenReturn(challengeModel);
        Mockito.when(cryptoUtils.hashInput("challenge")).thenReturn("challenge");

        assertTrue("", userController.checkChallenge(userModel, "challenge"));
    }

    /**
     * Method: checkChallenge(UserModel userModel, String solvedChallenge)
     */
    @Test
    public void testCheckChallengeNonExistingChallenge() throws Exception {
        Mockito.when(challengeController.searchChallengeForUser(userModel)).thenReturn(null);

        assertFalse("", userController.checkChallenge(userModel, "challenge"));
    }

    /**
     * Method: checkChallenge(UserModel userModel, String solvedChallenge)
     */
    @Test
    public void testCheckChallengeFailed() throws Exception {
        ChallengeModel challengeModel = new ChallengeModel("challenge", userModel);
        Mockito.when(challengeController.searchChallengeForUser(userModel)).thenReturn(challengeModel);

        assertFalse("", userController.checkChallenge(userModel, "wrongChallenge"));
    }

    /**
     * Method: changeEmailAddress(String emailOld, String emailNew)
     */
    @Test
    public void testChangeEmailAddress() throws Exception {
        Mockito.when(userRepository.findUserByEmail(emailPG)).thenReturn(userModel);
        UserModel changed = userController.changeEmailAddress(emailPG, emailPG1);

        assertEquals("", emailPG1, changed.getEmail());
    }

    /**
     * Method: changeEmailAddress(String emailOld, String emailNew)
     */
    @Test
    public void testChangeEmailAddressDuplicateMail() throws Exception {
        Mockito.when(userRepository.findUserByEmail(emailPGE)).thenReturn(userModel2);
        Mockito.when(userRepository.save(any(UserModel.class))).thenThrow(new DataIntegrityViolationException("Duplicate mail entry"));

        assertNull("", userController.changeEmailAddress(emailPGE, emailPG));
    }

    /**
     * Method: changeEmailAddress(String emailOld, String emailNew)
     */
    @Test
    public void testChangeEmailAddressNonExistingMail() throws Exception {
        Mockito.when(userRepository.findUserByEmail(emailPG)).thenReturn(null);

        assertNull("", userController.changeEmailAddress(emailPG, emailPG1));
    }

    /**
     * Method: changeEmailAddress(String emailOld, String emailNew)
     */
    @Test
    public void testChangeEmailAddressNonExisitingUser() throws Exception {
        Mockito.when(userRepository.findUserByEmail(emailPG)).thenReturn(null);

        assertNull("", userController.changeEmailAddress(emailPG, emailPG1));
    }

    /**
     * Method: getPublicKeyByIdentifier(String identifier)
     */
    @Test
    public void testGetPublicKeyByIdentifier() throws Exception {
        String keyId = "keyPG";
        userModel.setKeyNameIdentifier(keyId);
        userModel.setPublicKey(pubKey);
        Mockito.when(userRepository.findUserByKeyNameIdentifier(keyId)).thenReturn(userModel);

        assertEquals("", pubKey, userController.getPublicKeyByIdentifier(keyId));
        assertNull("", userController.getPublicKeyByIdentifier(keyId + "None"));
    }

    /**
     * Method: addWrappedKey(UserModel userModel, String wrappedKey)
     */
    @Test
    public void testAddWrappedKey() throws Exception {
        String wrappedKey = "wrappedKey";

        userController.addWrappedKey(userModel, wrappedKey);
        assertEquals("", wrappedKey, userModel.getWrappedKey());
    }

    /**
     * Method: addWrappedKey(UserModel userModel, String wrappedKey)
     */
    @Test
    public void testAddWrappedKeyNonExistingUser() throws Exception {
        String wrappedKey = "wrappedKey";

        assertNull("", userController.addWrappedKey(null, wrappedKey));
    }

    /**
     * Method: getUser(String email)
     */
    @Test
    public void testGetUserExistingUser() throws Exception {
        Mockito.when(userController.searchUser(emailPG)).thenReturn(userModel);

        assertEquals("", userModel.getEmail(), userController.getUser(emailPG).getEmail());
    }

    /**
     * Method: getUser(String email)
     */
    @Test
    public void testGetUserNonExistingUser() throws Exception {
        Mockito.when(userController.searchUser(emailPG)).thenReturn(null);
        Mockito.when(userController.createUser(emailPG)).thenReturn(userModel);

        assertEquals("", userModel.getEmail(), userController.getUser(emailPG).getEmail());
    }

    /**
     * Method: getUser(String email)
     */
    @Test
    public void testGetUserNotExistingUser() throws Exception {
        Mockito.when(userController.getUser(emailPG1)).thenReturn(new UserModel(emailPG1));

        assertEquals("", emailPG1, userController.getUser(emailPG1).getEmail());
    }

    /**
     * Method: searchUser(String email)
     */
    @Test
    public void testSearchUser() throws Exception {
        Mockito.when(userRepository.findUserByEmail(emailPG)).thenReturn(userModel);

        assertEquals("", userModel, userController.searchUser(emailPG));
    }

    /**
     * Method: searchUser(String email)
     */
    @Test
    public void testSearchUserNonExistingUser() throws Exception {
        assertNull("", userController.searchUser(emailPG1));
    }

    /**
     * Method: createUser(String email)
     */
    @Test
    public void testCreateUser() throws Exception {
        Mockito.when(userRepository.save(any(UserModel.class))).thenReturn(userModel);
        Method method = userController.getClass().getDeclaredMethod("createUser", String.class);
        method.setAccessible(true);

        assertEquals("", userModel.getEmail(), ((UserModel) method.invoke(userController, emailPG)).getEmail());
    }

    /**
     * Method: createUser(String email)
     */
    @Test
    public void testCreateUserExistingUser() throws Exception {
        Mockito.when(userRepository.save(any(UserModel.class))).thenThrow(new DataIntegrityViolationException("User already exists."));
        Method method = userController.getClass().getDeclaredMethod("createUser", String.class);
        method.setAccessible(true);

        assertNull("UserModel already exists, so it should be null.", method.invoke(userController, emailPG));
    }

    /**
     * Method: changeOAuthState(userModel userModel, UserStates oAuthTokenState)
     */
    @Test
    public void testChangeOAuthState() throws Exception {
        userController.changeOAuthState(userModel, UserStates.SENDWRAPPEDKEY);

        assertEquals("", UserStates.SENDWRAPPEDKEY, userModel.getState());
    }

    /**
     * Method: changeOAuthStateSendPubKey(userModel userModel)
     */
    @Test
    public void testChangeOAuthStateSendPubKey() throws Exception {
        userController.changeOAuthStateSendPubKey(userModel);

        assertEquals("", UserStates.SENDPUBKEY, userModel.getState());
    }

    /**
     * Method: changeOAuthStateAccessWrappedKey(userModel userModel)
     */
    @Test
    public void testChangeOAuthStateAccessWrappedKey() throws Exception {
        userController.changeOAuthStateAccessWrappedKey(userModel);

        assertEquals("", UserStates.ACCESSWRAPPEDKEY, userModel.getState());
    }

    /**
     * Method: changeOAuthStateSendWrappedKey(userModel userModel)
     */
    @Test
    public void testChangeOAuthStateSendWrappedKey() throws Exception {
        userController.changeOAuthStateSendWrappedKey(userModel);

        assertEquals("", UserStates.SENDWRAPPEDKEY, userModel.getState());
    }

    /**
     * Method: changeOAuthStateSolveChall(userModel userModel)
     */
    @Test
    public void testChangeOAuthStateSolveChall() throws Exception {
        userController.changeOAuthStateSolveChall(userModel);

        assertEquals("", UserStates.SOLVECHALL, userModel.getState());
    }

}
