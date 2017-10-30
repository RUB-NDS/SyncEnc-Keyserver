package com.master.keymanagementserver.kms.helpers;

import com.nimbusds.jose.util.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * ConversionHelper Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Oct 8, 2017</pre>
 */
@RunWith(JUnit4.class)
public class ConversionHelperTest {
    private String testString1 = "326F0F24CF";
    private String testString2 = "39B481983C3EA99A22DE";
    private String testString3 = "8FC2FF05E1B121E7069486B6902E68";
    private String testString4 = "8588C01D1317FB174B5270A9E714511026430881";

    private String encodedTestString1 = "MzI2RjBGMjRDRg==";
    private String encodedTestString2 = "MzlCNDgxOTgzQzNFQTk5QTIyREU=";
    private String encodedTestString3 = "OEZDMkZGMDVFMUIxMjFFNzA2OTQ4NkI2OTAyRTY4";
    private String encodedTestString4 = "ODU4OEMwMUQxMzE3RkIxNzRCNTI3MEE5RTcxNDUxMTAyNjQzMDg4MQ==";

    private byte[] bEmpty = new byte[]{};
    private byte[] b5 = new byte[]{50, 111, 15, 36, -49};
    private byte[] b10 = new byte[]{57, -76, -127, -104, 60, 62, -87, -102, 34, -34};
    private byte[] b15 = new byte[]{-113, -62, -1, 5, -31, -79, 33, -25, 6, -108, -122, -74, -112, 46, 104};
    private byte[] b20 = new byte[]{-123, -120, -64, 29, 19, 23, -5, 23, 75, 82, 112, -87, -25, 20, 81, 16, 38, 67, 8, -127};

    private String encodedB5 = "Mm8PJM8=";
    private String encodedB10 = "ObSBmDw+qZoi3g==";
    private String encodedB15 = "j8L/BeGxIecGlIa2kC5o";
    private String encodedB20 = "hYjAHRMX+xdLUnCp5xRRECZDCIE=";


    @Before
    public void before() throws Exception {
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: bytesToHex(byte[] bytes)
     */
    @Test
    public void testBytesToHex() throws Exception {
        assertEquals("", "", ConversionHelper.bytesToHex(bEmpty));
        assertEquals("", testString1, ConversionHelper.bytesToHex(b5));
        assertEquals("", testString2, ConversionHelper.bytesToHex(b10));
        assertEquals("", testString3, ConversionHelper.bytesToHex(b15));
        assertEquals("", testString4, ConversionHelper.bytesToHex(b20));
    }

    /**
     * Method: hexToBytes(String hexString)
     */
    @Test
    public void testHexToBytes() throws Exception {
        assertArrayEquals("assertion failed for empty String", bEmpty, ConversionHelper.hexToBytes(""));
        assertArrayEquals("assertion failed for String \"" + testString1 + "\"", b5, ConversionHelper.hexToBytes(testString1));
        assertArrayEquals("assertion failed for String \"" + testString2 + "\"", b10, ConversionHelper.hexToBytes(testString2));
        assertArrayEquals("assertion failed for String \"" + testString3 + "\"", b15, ConversionHelper.hexToBytes(testString3));
        assertArrayEquals("assertion failed for String \"" + testString4 + "\"", b20, ConversionHelper.hexToBytes(testString4));
    }

    @Test
    public void testHexToBytesAndBack() throws Exception {
        assertEquals("", "", ConversionHelper.bytesToHex(ConversionHelper.hexToBytes("")));
        assertEquals("", testString1, ConversionHelper.bytesToHex(ConversionHelper.hexToBytes(testString1)));
        assertEquals("", testString2, ConversionHelper.bytesToHex(ConversionHelper.hexToBytes(testString2)));
        assertEquals("", testString3, ConversionHelper.bytesToHex(ConversionHelper.hexToBytes(testString3)));
        assertEquals("", testString4, ConversionHelper.bytesToHex(ConversionHelper.hexToBytes(testString4)));
    }

    @Test
    public void testBytesToHexAndBack() throws Exception {
        assertArrayEquals("assertion failed for empty Byte-Array", bEmpty, ConversionHelper.hexToBytes(ConversionHelper.bytesToHex(bEmpty)));
        assertArrayEquals("assertion failed for Byte-Array with 5 values", b5, ConversionHelper.hexToBytes(ConversionHelper.bytesToHex(b5)));
        assertArrayEquals("assertion failed for Byte-Array with 10 values", b10, ConversionHelper.hexToBytes(ConversionHelper.bytesToHex(b10)));
        assertArrayEquals("assertion failed for Byte-Array with 15 values", b15, ConversionHelper.hexToBytes(ConversionHelper.bytesToHex(b15)));
        assertArrayEquals("assertion failed for Byte-Array with 20 values", b20, ConversionHelper.hexToBytes(ConversionHelper.bytesToHex(b20)));
    }

    /**
     * Method: base64EncodeBytes(byte[] bytes)
     */
    @Test
    public void testBase64EncodeBytes() throws Exception {
        assertEquals("", "", ConversionHelper.base64EncodeBytes(bEmpty).toString());
        assertEquals("", encodedB5, ConversionHelper.base64EncodeBytes(b5).toString());
        assertEquals("", encodedB10, ConversionHelper.base64EncodeBytes(b10).toString());
        assertEquals("", encodedB15, ConversionHelper.base64EncodeBytes(b15).toString());
        assertEquals("", encodedB20, ConversionHelper.base64EncodeBytes(b20).toString());
    }

    /**
     * Method: base64EncodeString(String string)
     */
    @Test
    public void testBase64EncodeString() throws Exception {
        assertEquals("", "", ConversionHelper.base64EncodeString("").toString());
        assertEquals("", encodedTestString1, ConversionHelper.base64EncodeString(testString1).toString());
        assertEquals("", encodedTestString2, ConversionHelper.base64EncodeString(testString2).toString());
        assertEquals("", encodedTestString3, ConversionHelper.base64EncodeString(testString3).toString());
        assertEquals("", encodedTestString4, ConversionHelper.base64EncodeString(testString4).toString());
    }

    /**
     * Method: base64DecodeToBytes(Base64 base64)
     */
    @Test
    public void testBase64DecodeToBytes() throws Exception {
        assertArrayEquals("assertion failed for empty encoded String", bEmpty, ConversionHelper.base64DecodeToBytes(new Base64("")));
        assertArrayEquals("assertion failed for encoded " + encodedB5 + " String", b5, ConversionHelper.base64DecodeToBytes(new Base64(encodedB5)));
        assertArrayEquals("assertion failed for encoded " + encodedB10 + " String", b10, ConversionHelper.base64DecodeToBytes(new Base64(encodedB10)));
        assertArrayEquals("assertion failed for encoded " + encodedB15 + " String", b15, ConversionHelper.base64DecodeToBytes(new Base64(encodedB15)));
        assertArrayEquals("assertion failed for encoded " + encodedB20 + " String", b20, ConversionHelper.base64DecodeToBytes(new Base64(encodedB20)));
    }

    /**
     * Method: base64DecodeToString(Base64 base64)
     */
    @Test
    public void testBase64DecodeToString() throws Exception {
        assertEquals("", "", ConversionHelper.base64DecodeToString(new Base64("")));
        assertEquals("", testString1, ConversionHelper.base64DecodeToString(new Base64(encodedTestString1)));
        assertEquals("", testString2, ConversionHelper.base64DecodeToString(new Base64(encodedTestString2)));
        assertEquals("", testString3, ConversionHelper.base64DecodeToString(new Base64(encodedTestString3)));
        assertEquals("", testString4, ConversionHelper.base64DecodeToString(new Base64(encodedTestString4)));
    }


} 
