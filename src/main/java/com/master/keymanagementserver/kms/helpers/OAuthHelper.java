package com.master.keymanagementserver.kms.helpers;

import com.master.keymanagementserver.kms.controllers.OAuthController;
import com.master.keymanagementserver.kms.models.OAuthModel;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * privides functions for working with the tokens
 */
@Component
public class OAuthHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthHelper.class);

    private final OAuthController oAuthController;
    private final TimeHelper timeHelper;

    @Autowired
    public OAuthHelper(OAuthController oAuthController, TimeHelper timeHelper) {
        this.oAuthController = oAuthController;
        this.timeHelper = timeHelper;
    }

    /**
     * get the related token from database for the provided authorization string
     *
     * @param authorization the authorization string containing the bearer token
     * @return the related OAuthModel
     */
    public OAuthModel getOAuthTokenbyAuthHeader(String authorization) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("get the token by authorization header: "
                    , LogEncoderHelper.encodeLogEntry(authorization));
        }
        if (authorization == null || "".equals(authorization)) {
            LOGGER.error("no OAuth Token was given.");
            return null;
        }

        // Split the authorization string "bearer <token>"
        String[] splitted = authorization.split("\\s");
        if (!"bearer".equalsIgnoreCase(splitted[0]) || splitted.length < 2) {
            LOGGER.error("No bearer token was given.");

            return null;
        }

        // Search for the related token in the database and check the valid range
        OAuthModel oAuthModel = oAuthController.getOAuthTokenByTokenId(splitted[1]);
        if (oAuthModel == null || !timeHelper.checkTimeValidity(DateTime.now(), oAuthModel)) {
            LOGGER.error("no valid token found.");

            return null;
        }

        return oAuthModel;
    }

    /**
     * check if OAuthModel is provided and check if user called the correct URL
     * if no OAuthModel is provided return an error string
     * if the step is not correct return an error strinf
     *
     * @param oAuthModel    OAuthModel provided for the check
     * @param expectedState the expected state due to the called URL
     * @return an error string or an empty string if everything is fine
     */
    public String checkOAuthReturnErrorString(OAuthModel oAuthModel, String expectedState) {
        if (oAuthModel == null) {
            return "{\"error\":\"no OAuth Token found.\", \"todo\":\"send request with correct OAuthToken\"}";
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("check the expected state {} with the one stored {}"
                    , LogEncoderHelper.encodeLogEntry(expectedState)
                    , LogEncoderHelper.encodeLogEntry(oAuthModel.getUserModel().getState().toString()));
        }

        if (!expectedState.equals(oAuthModel.getUserModel().getState().toString())) {
            return "{\"error\":\"" + expectedState + " is not next step\"" +
                    ", \"todo\":\"" + oAuthModel.getUserModel().getState() + "\"}";
        }

        return "";
    }

}
