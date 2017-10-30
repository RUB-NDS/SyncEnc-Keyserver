package com.master.keymanagementserver.kms.crypto;

import com.master.keymanagementserver.kms.helpers.ConversionHelper;
import com.nimbusds.jose.util.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Randomness Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Okt 8, 2017</pre>
 */
@RunWith(JUnit4.class)
public class RandomnessTest {

    private static final String INPUT = "email";
    private static final String REGEX_RANDOM = "[0-9A-F]+";

    @Before
    public void before() throws Exception {
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: generateRandomBytes(Integer length)
     */
    @Test
    public void testGenerateRandomBytesDifferent() throws Exception {
        Randomness randomness = new Randomness();
        List<byte[]> list = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            list.add(randomness.generateRandomBytes(8));
            for (int j = 0; j < i; j++) {
                assertNotEquals("two generated Nonces are equal.", list.get(i), list.get(j));
            }
        }
    }

    /**
     * Method: generateRandomBytes(Integer length)
     */
    @Test
    public void testGenerateRandomBytesLength() throws Exception {
        Randomness randomness = new Randomness();
        for (int i = 0; i < 64; i++) {
            assertEquals("", randomness.generateRandomBytes(i).length, i);
        }
    }

    /**
     * Method: generateTokenWithDate(String input, Integer randLength)
     */
    @Test
    public void testGenerateTokenWithDate() throws Exception {
        Randomness randomness = new Randomness();
        String token = randomness.generateTokenWithDate(INPUT, 16);

        String decodedToken = ConversionHelper.base64DecodeToString(new Base64(token));
        String regexDate = "\\d{4}-\\d{2}-\\d{2}";
        String regexTime = "T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}\\+\\d{2}";
        assertTrue("", decodedToken.matches("^" + INPUT + regexDate + regexTime + ":" + REGEX_RANDOM + "$"));
    }

    /**
     * Method: generateTokenWithoutDate(String input, Integer randLength)
     */
    @Test
    public void testGenerateTokenWithoutDate() throws Exception {
        Randomness randomness = new Randomness();
        String token = randomness.generateTokenWithoutDate(INPUT, 16);

        String decodedToken = ConversionHelper.base64DecodeToString(new Base64(token));
        assertTrue("", decodedToken.matches("^" + INPUT + REGEX_RANDOM + "$"));
    }

}
