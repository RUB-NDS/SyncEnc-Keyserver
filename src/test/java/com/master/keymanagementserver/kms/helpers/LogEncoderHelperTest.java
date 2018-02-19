package com.master.keymanagementserver.kms.helpers;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.assertEquals;

/**
 * LogEncoderHelper Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Oct 9, 2017</pre>
 */
@RunWith(JUnit4.class)
public class LogEncoderHelperTest {

    @Before
    public void before() throws Exception {
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: encodeLogEntry(String message)
     */
    @Test
    public void testEncodeLogEntryNewline() throws Exception {
        String newlineString = "First String\r\nSecond Line";
        String expectedNewlineString = "First String__Second Line";
        assertEquals("newline and carriage return should be replaced.", expectedNewlineString, LogEncoderHelper.encodeLogEntry(newlineString));
    }

    /**
     * Method: encodeLogEntry(String message)
     */
    @Test
    public void testEncodeLogEntryHTML() throws Exception {
        String htmlString = "<html><head></head><body><h1>Überschrift</h1></body></html>";
        String expectedHtmlString = "&lt;html&gt;&lt;head&gt;&lt;/head&gt;&lt;body&gt;&lt;h1&gt;&Uuml;berschrift&lt;/h1&gt;&lt;/body&gt;&lt;/html&gt;";
        assertEquals("Html-Tags should be encoded.", expectedHtmlString, LogEncoderHelper.encodeLogEntry(htmlString));
    }

    /**
     * Method: encodeLogEntry(String message)
     */
    @Test
    public void testEncodeLogEntryNothingToEncode() throws Exception {
        String string = "this is just a lame text.";
        assertEquals("newline and carriage return should be replaced.", string, LogEncoderHelper.encodeLogEntry(string));
    }

    /**
     * Method: encodeLogEntry(String message)
     */
    @Test
    public void testEncodeLogEntryEmptyString() throws Exception {
        assertEquals("empty String should be returned if empty string is given.", "", LogEncoderHelper.encodeLogEntry(null));
    }

    /**
     * Method: encodeLogEntry(String message)
     */
    @Test
    public void testEncodeLogEntryNullString() throws Exception {
        assertEquals("empty String should be returned if null is given.", "", LogEncoderHelper.encodeLogEntry(null));
    }


} 
