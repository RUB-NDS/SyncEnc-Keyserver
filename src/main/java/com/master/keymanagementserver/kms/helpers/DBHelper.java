package com.master.keymanagementserver.kms.helpers;

import com.master.keymanagementserver.kms.controllers.AuthnRequestController;
import com.master.keymanagementserver.kms.controllers.ChallengeController;
import com.master.keymanagementserver.kms.controllers.OAuthController;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class DBHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(DBHelper.class);
    private static final String ERROR_DELETING = "can not delete old {}";

    private final AuthnRequestController authnRequestController;
    private final ChallengeController challengeController;
    private final OAuthController oAuthController;

    @Autowired
    public DBHelper(AuthnRequestController authnRequestController, ChallengeController challengeController,
                    OAuthController oAuthController) {
        this.authnRequestController = authnRequestController;
        this.challengeController = challengeController;
        this.oAuthController = oAuthController;
    }

    /**
     * Deletes old entries from the database
     * calls the controller that deletes the entries
     */
    public void deleteOldDataFromDB() {
        LOGGER.info("Delete old Entries in DB.");
        // actual DateTime that is passed to the functions
        Date now = (new DateTime()).toDate();
        if (!authnRequestController.deleteAllOldAuthnRequest(now)) {
            LOGGER.error(ERROR_DELETING, "AuthnRequests");
        }
        if (!challengeController.deleteOldChallenges(now)) {
            LOGGER.error(ERROR_DELETING, "Challenges");
        }
        if (!oAuthController.deleteOldTokens(now)) {
            LOGGER.error(ERROR_DELETING, "Tokens");
        }
    }
}
