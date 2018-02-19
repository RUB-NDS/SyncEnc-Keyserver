package com.master.keymanagementserver.kms.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.HtmlUtils;

public class LogEncoderHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(LogEncoderHelper.class);

    private LogEncoderHelper() {
    }

    /**
     * ensure no CRLF injection into logs for forging records
     *
     * @param message message needs to be encoded
     * @return encoded message
     */
    public static String encodeLogEntry(String message) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("encode the provided message for the Log");
        }
        // If no message is provided return an empty string
        if (message == null || message.equals("")) {
            return "";
        }

        return HtmlUtils.htmlEscape(message.replace('\n', '_').replace('\r', '_'));
    }
}
