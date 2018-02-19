package com.master.keymanagementserver.kms.crypto;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.MockitoAnnotations;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.Assert.*;

/**
 * ChallengeResponse Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Oct 9, 2017</pre>
 */
@RunWith(JUnit4.class)
public class CryptoUtilsTest {

    private String pubKeyString = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlIjoiQVFBQiIsImV4dCI6dHJ1ZSwia2V5X29wcyI6WyJlbmNyeXB0Il0sImt0eSI6IlJTQSIsIm4iOiJ2djRTQXpzTEZuWHozaWt1aDkxajA5dnZ4ZUVPZG1oRWVjLVFUelRoYjJQMjNhT0ktSTBCZzF0Rm5iUmZwZGRFeDRlQTlCbUE4RzQ0czBsTGhZMlloOWMwYTFKM2RCaWZLcTZLcFNpSWp3UjlManRiNGtTTjl2dkpCdEhKNk1TTmw0MDF6NDFXTnFxT0FpNi1uM0ZEYXhhQTNXdXR6OGs5UU5obkNpZG03blVwcjEweXZ4WUd3UGQyY0kwWTRUeXdZYzV0U29jLVp3NlpVdEtGUUlsS01fWFE0M2w2SDlnME9YRXJLNmN5WC1oYlFJWThoNVBLbEN2eEgyTUJCRHhrT1J3T0NtUW9BYWJXUVpQcDhOaVAxMS14VVk1X0dxUWlRZWVlQXRNaXROb1NEOU00ZkZvUjc0ZUdUaFpRTmRwbmNMbmtLUmNKdEkwTm9Dc1FzaDg1LWVEalpjUDE2WXVvdjA3alE5UDYtcG5wdVZJdm1SS2I5OUp1bEYwNFZ0QWc3WkJzUHFncVNMeTJyUFM1ZWhEaXljUFl5dEJPdUdGWXdoSktJZy1SYkxZSEpYanVteEQ3Y0YwbW5wcHBPbzROTzNXaEl1dDg0RTJRRHFMZUF0d1ZabU9hWlRFa21vOG5SRENQcnFsWWxLdU9wb3U3clZ6R2FMdmlWcHFQNjl6V3VwY29qZnhfR3RFR3dGWDZzT1JWVFR6U0dpQ2IxcFRzVlJNVHpILUdXdllkQ2VXbWhBY2xTa1RfSktnd2dqSFBLNV9jN3dHQkhjXzl1V0VEdHB5bDFydXlZUUZMNFRDSHdMS2J5T1ZYSlJZYU9RRlp4d1ZSaGxGWE1id3RLUjVTRFZRZ0t2TUduTmJLbXpSUnlBQVljQ1BBdjZQNGs4SmNqX1lqWDN1SVlUcyJ9";
    private CryptoUtils cryptoUtils;

    @Before
    public void before() throws Exception {
        MockitoAnnotations.initMocks(this);
        cryptoUtils = new CryptoUtils();
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: encryptChallenge(String challenge, String pubKey)
     */
    @Test
    public void testEncryptChallenge() throws Exception {
        assertNotNull("", CryptoUtils.encryptChallenge("challenge", pubKeyString));
    }

    /**
     * Method: encryptChallenge(String challenge, String pubKey)
     */
    @Test
    public void testEncryptChallengeInvalidKey() throws Exception {
        assertNull("", CryptoUtils.encryptChallenge("chall", "pubKey"));
    }


    /**
     * Method: generatePublicKeyOutOfPubKeyString(String pubKey)
     */
    @Test
    public void testGeneratePublicKeyOutOfPubKeyString() throws Exception {
        byte[] pubKeyBytes = new byte[]{48, -126, 2, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -126, 2, 15, 0, 48, -126, 2, 10, 2, -126, 2, 1, 0, -66, -2, 18, 3, 59, 11, 22, 117, -13, -34, 41, 46, -121, -35, 99, -45, -37, -17, -59, -31, 14, 118, 104, 68, 121, -49, -112, 79, 52, -31, 111, 99, -10, -35, -93, -120, -8, -115, 1, -125, 91, 69, -99, -76, 95, -91, -41, 68, -57, -121, -128, -12, 25, -128, -16, 110, 56, -77, 73, 75, -123, -115, -104, -121, -41, 52, 107, 82, 119, 116, 24, -97, 42, -82, -118, -91, 40, -120, -113, 4, 125, 46, 59, 91, -30, 68, -115, -10, -5, -55, 6, -47, -55, -24, -60, -115, -105, -115, 53, -49, -115, 86, 54, -86, -114, 2, 46, -66, -97, 113, 67, 107, 22, -128, -35, 107, -83, -49, -55, 61, 64, -40, 103, 10, 39, 102, -18, 117, 41, -81, 93, 50, -65, 22, 6, -64, -9, 118, 112, -115, 24, -31, 60, -80, 97, -50, 109, 74, -121, 62, 103, 14, -103, 82, -46, -123, 64, -119, 74, 51, -11, -48, -29, 121, 122, 31, -40, 52, 57, 113, 43, 43, -89, 50, 95, -24, 91, 64, -122, 60, -121, -109, -54, -108, 43, -15, 31, 99, 1, 4, 60, 100, 57, 28, 14, 10, 100, 40, 1, -90, -42, 65, -109, -23, -16, -40, -113, -41, 95, -79, 81, -114, 127, 26, -92, 34, 65, -25, -98, 2, -45, 34, -76, -38, 18, 15, -45, 56, 124, 90, 17, -17, -121, -122, 78, 22, 80, 53, -38, 103, 112, -71, -28, 41, 23, 9, -76, -115, 13, -96, 43, 16, -78, 31, 57, -7, -32, -29, 101, -61, -11, -23, -117, -88, -65, 78, -29, 67, -45, -6, -6, -103, -23, -71, 82, 47, -103, 18, -101, -9, -46, 110, -108, 93, 56, 86, -48, 32, -19, -112, 108, 62, -88, 42, 72, -68, -74, -84, -12, -71, 122, 16, -30, -55, -61, -40, -54, -48, 78, -72, 97, 88, -62, 18, 74, 34, 15, -111, 108, -74, 7, 37, 120, -18, -101, 16, -5, 112, 93, 38, -98, -102, 105, 58, -114, 13, 59, 117, -95, 34, -21, 124, -32, 77, -112, 14, -94, -34, 2, -36, 21, 102, 99, -102, 101, 49, 36, -102, -113, 39, 68, 48, -113, -82, -87, 88, -108, -85, -114, -90, -117, -69, -83, 92, -58, 104, -69, -30, 86, -102, -113, -21, -36, -42, -70, -105, 40, -115, -4, 127, 26, -47, 6, -64, 85, -6, -80, -28, 85, 77, 60, -46, 26, 32, -101, -42, -108, -20, 85, 19, 19, -52, 127, -122, 90, -10, 29, 9, -27, -90, -124, 7, 37, 74, 68, -1, 36, -88, 48, -126, 49, -49, 43, -97, -36, -17, 1, -127, 29, -49, -3, -71, 97, 3, -74, -100, -91, -42, -69, -78, 97, 1, 75, -31, 48, -121, -64, -78, -101, -56, -27, 87, 37, 22, 26, 57, 1, 89, -57, 5, 81, -122, 81, 87, 49, -68, 45, 41, 30, 82, 13, 84, 32, 42, -13, 6, -100, -42, -54, -101, 52, 81, -56, 0, 24, 112, 35, -64, -65, -93, -8, -109, -62, 92, -113, -10, 35, 95, 123, -120, 97, 59, 2, 3, 1, 0, 1};
        PublicKey publicKey = CryptoUtils.generatePublicKeyOutOfPubKeyString(pubKeyString);
        if (publicKey == null) {
            fail("publicKey shall not be null");
        }

        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        BigInteger modulus = new BigInteger("779181266065852407427028956208710129557409154458096164758674481719017876362431808369483737703941716056031502272095058567040899542880222998457835676030093313125820643613816494903692342357446838770444800056392189238179561802720517830123014501790990622219017964401388518962477082238704175757533309748632146084171776716209915911828578851663972461915884326145938862308377497261408713708069408950337901103442894376697768845669106748318147967317166990691817505171105678802763787390475667622122913084182113149541247226508303984634505654621621181087053686546483919749729239954982598493000562168697782645903742746736461093759000975455110677512562861471628618302653247855403883526725087839417501366159552297181083074065644196751967866449797996720707238271487609238229813912929195466762817230293168313752020490235304440760017355842912032346860434689992051670485276246183655356139660023339134515136522579873180851104334652947855831737842792610847296986622652384443628952898701920512234757349688231107383251822209495081789034212761258972461612425778499325564874865212336349634998694887533171130198106435602103338224998479893270196264116271461945808901194735753627351817907368530509069717563486257496667908109946527511496581604550476136298960150843");
        assertEquals("Algorithm should be RSA", "RSA", publicKey.getAlgorithm());
        assertEquals("public Exponent should be 65537", BigInteger.valueOf(65537), rsaPublicKey.getPublicExponent());
        assertEquals("modulus should be equal to the saved one", modulus, rsaPublicKey.getModulus());
        assertArrayEquals("pubKeyBytes should equal saved one", pubKeyBytes, publicKey.getEncoded());
    }

    /**
     * Method: generatePublicKeyOutOfPubKeyString(String pubKey)
     */
    @Test
    public void testGeneratePublicKeyOutOfPubKeyStringNonValidString() throws Exception {
        String pubKeyString = "";
        PublicKey publicKey = CryptoUtils.generatePublicKeyOutOfPubKeyString(pubKeyString);

        assertNull("", publicKey);
    }

    /**
     * Method: hashInput(String input)
     */
    @Test
    public void testHashInput() throws Exception {
        String emptyInput = "";
        String expectedEmptyOutput = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        String emptyOutput = cryptoUtils.hashInput(emptyInput);
        assertEquals("", expectedEmptyOutput, emptyOutput);

        String shortInput = "challenge";
        String expectedShortOutput = "8dc46595f7dc00d730463b109c1ca3c81981f7ce9c87c9fcb99107a03861de62f01f541a9678453bf267c5a1b109cb9a9550e36806248e1592a080ccba90fc43";
        String shortOutput = cryptoUtils.hashInput(shortInput);
        assertEquals("", expectedShortOutput, shortOutput);

        String longInput = "veryveryveryveryveryveryveryveryveryveryveryverylongInput";
        String expectedLongOutput = "e2211ea7b632b668d0fed8f9641c63f866272d2b4f0c46543ce514636719119d95f1a5785f7e894bef087857c47a2488ef11703aec2a17c66c9048db144d53c9";
        String longOutput = cryptoUtils.hashInput(longInput);
        assertEquals("", expectedLongOutput, longOutput);
    }
}
