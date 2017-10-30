package com.master.keymanagementserver.kms.models;

import com.master.keymanagementserver.kms.controllers.UserController;
import com.master.keymanagementserver.kms.repositories.UserRepository;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import static org.junit.Assert.assertEquals;

/**
 * UserModel Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Oct 14, 2017</pre>
 */
public class UserModelTest {
    @Mock
    UserRepository userRepository;
    @Mock
    UserController userController;

    UserModel userModel;

    @Before
    public void before() throws Exception {
        userModel = new UserModel("pg@rub.de");
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: getKeyNameIdentifier()
     */
    @Test
    public void testGetKeyNameIdentifier() throws Exception {
        userModel.setKeyNameIdentifier("test");
        assertEquals("", "test", userModel.getKeyNameIdentifier());
    }

    /**
     * Method: getEmail()
     */
    @Test
    public void testGetEmail() throws Exception {
        assertEquals("", "pg@rub.de", userModel.getEmail());
    }

    /**
     * Method: setEmail(String email) & getEmail
     */
    @Test
    public void testSetEmail() throws Exception {
        userModel.setEmail("test@rub.de");

        assertEquals("", "test@rub.de", userModel.getEmail());
    }

    /**
     * Method: getWrappedKey() & setWrappedKey(String wrappedKey)
     */
    @Test
    public void testGetWrappedKey() throws Exception {
        userModel.setWrappedKey("testWrappedKey");

        assertEquals("", "testWrappedKey", userModel.getWrappedKey());
    }

    /**
     * Method: getPublicKey() & setPublicKey(String publicKey)
     */
    @Test
    public void testGetPublicKey() throws Exception {
        userModel.setPublicKey("testPubKey");

        assertEquals("", "testPubKey", userModel.getPublicKey());
    }

    /**
     * Method: getSalt() & setSalt(String salt)
     */
    @Test
    public void testGetSalt() throws Exception {
        userModel.setSalt("testSalt");

        assertEquals("", "testSalt", userModel.getSalt());
    }

} 
