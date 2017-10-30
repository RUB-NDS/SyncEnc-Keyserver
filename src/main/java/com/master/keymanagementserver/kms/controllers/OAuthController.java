package com.master.keymanagementserver.kms.controllers;

import com.master.keymanagementserver.kms.helpers.LogEncoderHelper;
import com.master.keymanagementserver.kms.models.OAuthModel;
import com.master.keymanagementserver.kms.models.UserModel;
import com.master.keymanagementserver.kms.repositories.OAuthRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Controller;

import java.util.Date;

/**
 * provide functions for working with the oAuthModel
 */
@Controller
public class OAuthController {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthController.class);
    private static final String ERROR_NO_USER_MODEL_GIVEN = "Got null instead of a userModel.";

    private final OAuthRepository oAuthRepository;

    @Autowired
    public OAuthController(OAuthRepository oAuthRepository) {
        this.oAuthRepository = oAuthRepository;
    }

    /**
     * create a new token for the provided user with the provided tokentype
     *
     * @param userModel the userModel which has to get a token
     * @param tokenType the type of the token (actual just access)
     * @return the created OAuthModel, null if error occurred
     */
    OAuthModel createOAuthTokenForUser(UserModel userModel, String tokenType) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("create token with type {} for user {}"
                    , LogEncoderHelper.encodeLogEntry(tokenType)
                    , LogEncoderHelper.encodeLogEntry(userModel.getEmail()));
        }
        // if no userModel provided return null
        if (userModel == null) {
            LOGGER.warn(ERROR_NO_USER_MODEL_GIVEN);

            return null;
        }
        // Create new OAuthModel, if exception is thrown return null
        OAuthModel oAuthModel = new OAuthModel(tokenType, userModel);
        try {
            oAuthRepository.save(oAuthModel);
        } catch (DataIntegrityViolationException e) {
            LOGGER.error("OAuth-Token already exists.");

            return null;
        }

        return oAuthModel;
    }

    /**
     * get the token with the provided tokenid
     *
     * @param oAuthTokenId tokenId that is searched
     * @return OAuthModel with the provided tokenId, null if error occurred
     */
    public OAuthModel getOAuthTokenByTokenId(String oAuthTokenId) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("get token with id {}"
                    , LogEncoderHelper.encodeLogEntry(oAuthTokenId));
        }
        // return null if no tokenId provided
        if ("".equals(oAuthTokenId)) {
            LOGGER.error("oAuthTokenId was empty.");

            return null;
        }

        // if no OAuthModel found return null
        OAuthModel oAuthModel = null;
        try {
            oAuthModel = oAuthRepository.findOAuthModelByTokenId(oAuthTokenId);
        } catch (NullPointerException e) {
            LOGGER.error("No OAuth Token with this id found. {}", e);

            return null;
        }

        return oAuthModel;
    }

    /**
     * get OAuth Token for userModel
     * get existing or create new one
     *
     * @param userModel the userModel which has to get a token
     * @return the OAuthModel which was created or found, null if error occured
     */
    public OAuthModel getOAuthToken(UserModel userModel) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("get token for user {}"
                    , LogEncoderHelper.encodeLogEntry(userModel.getEmail()));
        }
        if (userModel == null) {
            LOGGER.warn(ERROR_NO_USER_MODEL_GIVEN);
            return null;
        }

        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("first search it");
        }
        // if no token exists, create a new one
        OAuthModel oAuthModel = searchOAuthModel(userModel);
        if (oAuthModel == null) {
            if(LOGGER.isDebugEnabled()){
                LOGGER.debug("if not exists create it");
            }
            oAuthModel = createOAuthTokenForUser(userModel, "access");
        }

        return oAuthModel;
    }

    /**
     * search the token belonging to the provided userModel
     *
     * @param userModel userModel which token should be returned
     * @return the found token for userModel, null error occurred
     */
    OAuthModel searchOAuthModel(UserModel userModel) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("search token for user {}"
                    , LogEncoderHelper.encodeLogEntry(userModel.getEmail()));
        }
        if (userModel == null) {
            LOGGER.error(ERROR_NO_USER_MODEL_GIVEN);

            return null;
        }

        // return null if no token for the user found
        OAuthModel oAuthModel = null;
        try {
            oAuthModel = oAuthRepository.findOAuthModelByUserModel(userModel);
        } catch (NullPointerException e) {
            LOGGER.info("No oAuthModel found for the User {}", userModel.getEmail());

            return null;
        }

        return oAuthModel;
    }

    /**
     * delete old tokens stored in the database
     * tokens just have limited valid range
     *
     * @param now the Date, everything with notValidAfter before this will be deleted
     * @return true
     */
    public boolean deleteOldTokens(Date now) {
        LOGGER.info("Delete all old OAuthToken.");
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("All being before: {}"
                    , now);
        }

        Iterable<OAuthModel> oAuthIterable = oAuthRepository.findOAuthModelsByNotValidAfterBefore(now);

        for (OAuthModel oAuthModel : oAuthIterable) {
            LOGGER.info("OAuthToken for user ({}) was old and so deleted", oAuthModel.getUserModel().getEmail());
            oAuthRepository.delete(oAuthModel);
        }

        return true;
    }
}
