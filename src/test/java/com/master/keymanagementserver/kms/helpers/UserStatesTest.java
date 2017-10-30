package com.master.keymanagementserver.kms.helpers;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * UserStates Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Oct 10, 2017</pre>
 */
public class UserStatesTest {

    @Before
    public void before() throws Exception {
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: toString()
     */
    @Test
    public void testToString() throws Exception {
        assertEquals("", "SENDPUBKEY", UserStates.SENDPUBKEY.toString());
        assertEquals("", "ACCESSWRAPPEDKEY", UserStates.ACCESSWRAPPEDKEY.toString());
        assertEquals("", "SENDWRAPPEDKEY", UserStates.SENDWRAPPEDKEY.toString());
        assertEquals("", "SOLVECHALL", UserStates.SOLVECHALL.toString());
    }


} 
