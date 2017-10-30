package com.master.keymanagementserver.kms.controllers;

import com.master.keymanagementserver.kms.crypto.CryptoUtils;
import com.master.keymanagementserver.kms.crypto.Randomness;
import com.master.keymanagementserver.kms.helpers.ConversionHelper;
import com.master.keymanagementserver.kms.helpers.LogEncoderHelper;
import com.master.keymanagementserver.kms.helpers.UserStates;
import com.master.keymanagementserver.kms.models.ChallengeModel;
import com.master.keymanagementserver.kms.models.UserModel;
import com.master.keymanagementserver.kms.repositories.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Controller;
import sun.rmi.runtime.Log;

/**
 * provide functions for working with the userModel
 */
@Controller
public class UserController {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);
    private static final Integer SALT_LENGTH = 32;

    private final UserRepository userRepository;
    private final ChallengeController challengeController;
    private final Randomness randomness;
    private final CryptoUtils cryptoUtils;


    @Autowired
    public UserController(UserRepository userRepository, ChallengeController challengeController,
                          Randomness randomness, CryptoUtils cryptoUtils) {
        this.userRepository = userRepository;
        this.challengeController = challengeController;
        this.randomness = randomness;
        this.cryptoUtils = cryptoUtils;
    }

    /**
     * search the belonging userModel
     *
     * @param email email from the searched userModel
     * @return the requested user model or null if not found
     */
    public UserModel searchUser(String email) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("search user with mail: {}", LogEncoderHelper.encodeLogEntry(email));
        }
        UserModel userModel = userRepository.findUserByEmail(email);

        if (userModel == null) {
            LOGGER.info("No User Model found for the email ({})", email);

            return null;
        }

        return userModel;
    }

    /**
     * create a userModel with the provided email
     *
     * @param email email of the userModel that needs to be created
     * @return the createdUserModel or null if exception was thrown
     */
    UserModel createUser(String email) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("create user with mail: {}", LogEncoderHelper.encodeLogEntry(email));
        }

        UserModel newUserModel = new UserModel(email);
        try {
            userRepository.save(newUserModel);
        } catch (DataIntegrityViolationException e) {
            LOGGER.error("UserModel with this email exists already. {}", e);

            return null;
        }

        return newUserModel;
    }

    /**
     * add publicKey to the userModel with the given email
     *
     * @param email  email of the userModel which publicKey should be set
     * @param pubKey publicKey that should be set
     * @return the userModel where the publicKey was set or null if an error occured
     */
    public UserModel addPublicKey(String email, String pubKey) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("the user with the mail '{}' got this pubKey '{}'"
                    , LogEncoderHelper.encodeLogEntry(email)
                    , LogEncoderHelper.encodeLogEntry(pubKey));
        }
        // search the user and return null if no userModel was found
        UserModel userModel = searchUser(email);
        if (userModel == null) {
            return null;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("create salt");
        }
        // create the bytes for the salt randomly, encode base64 and set to the userModel
        byte[] saltBytes = randomness.generateRandomBytes(SALT_LENGTH);
        String generatedSalt = ConversionHelper.base64EncodeBytes(saltBytes).toString();
        userModel.setSalt(generatedSalt);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("create keyNameID");
        }
        // create the keyNameIdentifier randomly and set to the userModel
        String keyNameIdentifier = randomness.generateTokenWithDate("keyNameID", 3);
        userModel.setKeyNameIdentifier(keyNameIdentifier);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("setPubKey");
        }
        // set the provided publicKey to the userModel
        userModel.setPublicKey(pubKey);

        // try to save the userModel
        try {
            userRepository.save(userModel);
        } catch (DataIntegrityViolationException e) {
            // in case of an error, try a new keyNameIdentifier
            LOGGER.warn("DataIntegrityViolationException: {}", e);
            try {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("try new keyNameID");
                }
                userModel.setKeyNameIdentifier(randomness.generateTokenWithDate("keyNameID", 3));
                userRepository.save(userModel);
            } catch (DataIntegrityViolationException ex) {
                // in case of an error return null
                LOGGER.error("Error saving the public key. {}", ex);

                return null;
            }
        }

        return userModel;
    }

    /**
     * checks the provided challenge with the saved sha-512 hash of the original challenge
     *
     * @param userModel       userModel which challenge should be checked
     * @param solvedChallenge the challenge that may be correct
     * @return true if the challenge is the one in the database, false otherwise
     */
    public boolean checkChallenge(UserModel userModel, String solvedChallenge) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("check the challenge {} for the user {}"
                    , LogEncoderHelper.encodeLogEntry(solvedChallenge)
                    , LogEncoderHelper.encodeLogEntry(userModel.getEmail()));
        }
        // get the sha-512 hashed challenge from database
        ChallengeModel challengeModel = challengeController.searchChallengeForUser(userModel);
        if (challengeModel == null) {
            // return false if no challenge exists
            LOGGER.error("No challenge for this user exists.");

            return false;
        }

        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("expected challenge {}", LogEncoderHelper.encodeLogEntry(challengeModel.getChallenge()));
        }
        // check if the hashed provided challenge is equal to the saved on in the database
        return challengeModel.getChallenge().equals(cryptoUtils.hashInput(solvedChallenge));
    }

    /**
     * change the email-address of a user
     *
     * @param emailOld old email of the user
     * @param emailNew new usermodel
     * @return the userModel which email-address was changed, null if an error occured
     */
    UserModel changeEmailAddress(String emailOld, String emailNew) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("change this mail {} to this {}"
                    , LogEncoderHelper.encodeLogEntry(emailOld)
                    , LogEncoderHelper.encodeLogEntry(emailNew));
        }
        // return null if no userModel was found with the provided old email-address
        UserModel userModel = searchUser(emailOld);
        if (userModel == null) {
            LOGGER.error("There is no User with the given old email ({}).", LogEncoderHelper.encodeLogEntry(emailOld));

            return null;
        }

        // Try to change the email, in case of error return null
        try {
            userModel.setEmail(emailNew);
            userRepository.save(userModel);
        } catch (DataIntegrityViolationException e) {
            LOGGER.error("Could not change email because address already exists.");

            return null;
        }

        return userModel;
    }

    /**
     * find the public key by the provided identifier
     *
     * @param identifier the keynameidentifier of the wanted public key
     * @return publicKey string that was requested, null if none found
     */
    public String getPublicKeyByIdentifier(String identifier) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("Looking for pubKey with identifier ({})", LogEncoderHelper.encodeLogEntry(identifier));
        }
        try {
            UserModel userModel = userRepository.findUserByKeyNameIdentifier(identifier);

            return userModel.getPublicKey();
        } catch (NullPointerException e) {
            LOGGER.error("No User found with this identifier.", e);

            return null;
        }
    }

    /**
     * add provided wrapped key to the provided userModel
     *
     * @param userModel  userModel which wrappedKey needs to be added
     * @param wrappedKey wrappedKey of the userModel
     * @return the userModel which wrappedKey was added, null if error occured
     */
    public UserModel addWrappedKey(UserModel userModel, String wrappedKey) {
        if (userModel == null) {

            return null;
        }
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("add wrappedKey {} to user {}"
                    , LogEncoderHelper.encodeLogEntry(wrappedKey)
                    , LogEncoderHelper.encodeLogEntry(userModel.getEmail()));
        }

        userModel.setWrappedKey(wrappedKey);
        userRepository.save(userModel);

        return userModel;
    }

    /**
     * get user
     * if the user is not in the database create it
     *
     * @param email the email of the userModel that should searched or created
     * @return userModel that was found or created
     */
    public UserModel getUser(String email) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("get user with email: {}", LogEncoderHelper.encodeLogEntry(email));
            LOGGER.debug("first search it");
        }
        UserModel userModel = searchUser(email);

        // if userModel found return it
        if (userModel != null) {
            return userModel;
        }
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("does not exist so create it");
        }
        // otherwise create a new userModel
        userModel = createUser(email);

        return userModel;
    }

    /**
     * change the state of the token
     *
     * @param userModel  userModel which state has to be changed
     * @param userStates the state the oAuthModel will set to
     */
    void changeOAuthState(UserModel userModel, UserStates userStates) {
        userModel.setState(userStates);
        userRepository.save(userModel);
    }

    /**
     * change OAuthModel to SendPubKey
     *
     * @param userModel userModel which state has to be changed
     * @return true, for checking in if
     */
    public boolean changeOAuthStateSendPubKey(UserModel userModel) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("change state to SENDPUBKEY of {}"
                    , LogEncoderHelper.encodeLogEntry(userModel.getEmail()));
        }
        changeOAuthState(userModel, UserStates.SENDPUBKEY);

        return true;
    }

    /**
     * change OAuthModel to AccessWrappedKey
     *
     * @param userModel oAuthModel which state has to be changed
     * @return true, for checking in if
     */
    public boolean changeOAuthStateAccessWrappedKey(UserModel userModel) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("change state to ACCESSWRAPPEDKEY of {}"
                    , LogEncoderHelper.encodeLogEntry(userModel.getEmail()));
        }
        changeOAuthState(userModel, UserStates.ACCESSWRAPPEDKEY);

        return true;
    }

    /**
     * change OAuthModel to SendWrappedKey
     *
     * @param userModel oAuthModel which state has to be changed
     * @return true, for checking in if
     */
    public boolean changeOAuthStateSendWrappedKey(UserModel userModel) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("change state to SENDWRAPPEDKEY of {}"
                    , LogEncoderHelper.encodeLogEntry(userModel.getEmail()));
        }
        changeOAuthState(userModel, UserStates.SENDWRAPPEDKEY);

        return true;
    }

    /**
     * change OAuthModel to SolveChallenge
     *
     * @param userModel oAuthModel which state has to be changed
     * @return true, for checking in if
     */
    public boolean changeOAuthStateSolveChall(UserModel userModel) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("change state to SOLVECHALL of {}"
                    , LogEncoderHelper.encodeLogEntry(userModel.getEmail()));
        }
        changeOAuthState(userModel, UserStates.SOLVECHALL);

        return true;
    }


}
