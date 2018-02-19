package com.master.keymanagementserver.kms.controllers;

import com.master.keymanagementserver.kms.crypto.CryptoUtils;
import com.master.keymanagementserver.kms.crypto.Randomness;
import com.master.keymanagementserver.kms.helpers.ConversionHelper;
import com.master.keymanagementserver.kms.helpers.LogEncoderHelper;
import com.master.keymanagementserver.kms.models.ChallengeModel;
import com.master.keymanagementserver.kms.models.UserModel;
import com.master.keymanagementserver.kms.repositories.ChallengeRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Controller;

import java.util.Date;

/**
 * provide functions for working with the challengeModel
 */
@Controller
public class ChallengeController {
    private static final Logger LOGGER = LoggerFactory.getLogger(ChallengeController.class);
    private static final Integer CHALLENGE_LENGTH = 64;

    private final ChallengeRepository challengeRepository;
    private final Randomness randomness;
    private final CryptoUtils cryptoUtils;

    @Autowired
    public ChallengeController(ChallengeRepository challengeRepository,
                               Randomness randomness, CryptoUtils cryptoUtils) {
        this.challengeRepository = challengeRepository;
        this.randomness = randomness;
        this.cryptoUtils = cryptoUtils;
    }

    /**
     * create new challenge for provided userModel
     * the sha-512 hash will be stored
     *
     * @param userModel userModel the challenge is created for
     * @return the not hashed challenge, null if error occurred
     */
    String createChallengeForUser(UserModel userModel) {
        if (userModel == null) {
            LOGGER.error("Got null instead of a userModel.");

            return null;
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("create challenge for user {}"
                    , LogEncoderHelper.encodeLogEntry(userModel.getUsername()));
        }

        // generate random challenge with CHALLENGE_LENGTH bytes
        byte[] challengeBytes = randomness.generateRandomBytes(CHALLENGE_LENGTH);
        // base64 encode the challenge bytes and hash it
        String challenge = ConversionHelper.base64EncodeBytes(challengeBytes).toString();
        String hashedChallenge = cryptoUtils.hashInput(challenge);

        // create the challengeModel for the provided user with the hashedChallenge, return null if failed
        ChallengeModel createdChallengeModel = new ChallengeModel(hashedChallenge, userModel);
        try {
            challengeRepository.save(createdChallengeModel);
        } catch (DataIntegrityViolationException e) {
            LOGGER.error("Challenge already exists.");
            return null;
        }

        return challenge;
    }

    /**
     * Search the challenge for the provided userModel
     *
     * @param userModel userModel which challenge is searched
     * @return challengeModel for the provided userModel, null if error occured
     */
    ChallengeModel searchChallengeForUser(UserModel userModel) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("search challenge for user {}"
                    , LogEncoderHelper.encodeLogEntry(userModel.getUsername()));
        }
        ChallengeModel challengeModel;

        // return null if no challenge for the user found
        try {
            challengeModel = challengeRepository.findChallengeByUserModel(userModel);
        } catch (NullPointerException e) {
            LOGGER.warn("No Challenge for User {} exists.", userModel.getUsername());
            LOGGER.warn("NPE: {}", e);

            return null;
        }

        return challengeModel;
    }

    /**
     * get challenge for the provided user
     * if it does not exist it will be created
     *
     * @param userModel userModel the challenge is searched or created for
     * @return the not hashed challenge
     */
    public String getChallengeForUser(UserModel userModel) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("get challenge for user {}"
                    , LogEncoderHelper.encodeLogEntry(userModel.getUsername()));
        }
        ChallengeModel challengeModel;

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("first search it");
        }
        // if challenge for the userModel found return it, create new otherwise
        challengeModel = searchChallengeForUser(userModel);
        if (challengeModel != null) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("does not exists so create it");
            }

            return challengeModel.getChallenge();
        }

        return createChallengeForUser(userModel);
    }

    /**
     * delete old challenges stored in the database
     * challenges just have limited valid range
     *
     * @param now the Date, everything with notValidAfter before this will be deleted
     * @return true
     */
    public boolean deleteOldChallenges(Date now) {
        LOGGER.info("Delete all old challenges.");
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("All being before: {}"
                    , LogEncoderHelper.encodeLogEntry(now.toString()));
        }

        Iterable<ChallengeModel> challengeIterable = challengeRepository.findChallengesByNotValidAfterIsBefore(now);

        for (ChallengeModel challengeModel : challengeIterable) {
            LOGGER.info("Challenge for user ({}) was old and so deleted", challengeModel.getUserModel().getUsername());
            challengeRepository.delete(challengeModel);
        }

        return true;
    }
}
