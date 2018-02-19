package com.master.keymanagementserver.kms.controllers;

import com.master.keymanagementserver.kms.helpers.LogEncoderHelper;
import com.master.keymanagementserver.kms.models.AuthnRequestModel;
import com.master.keymanagementserver.kms.repositories.AuthnRequestRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Controller;

import java.util.Date;

/**
 * provide functions for working with the authnRequestModel
 */
@Controller
public class AuthnRequestController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthnRequestController.class);

    private final AuthnRequestRepository authnRequestRepository;

    @Autowired
    public AuthnRequestController(AuthnRequestRepository authnRequestRepository) {
        this.authnRequestRepository = authnRequestRepository;
    }

    /**
     * create new authnRequest with provided relayState and issuer
     *
     * @param relayState relayState included in the authnRequest
     * @param issuer     issuer of the authnRequest
     * @return created authnRequestModel, null if error occurred
     */
    public AuthnRequestModel createAuthnRequest(String username, String relayState, String issuer) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("create AuthnRequest with relayState '{}' and issuer '{}'"
                    , LogEncoderHelper.encodeLogEntry(relayState)
                    , LogEncoderHelper.encodeLogEntry(issuer));
        }
        // try to save authnRequestModel
        AuthnRequestModel authnRequestModel = new AuthnRequestModel(username, relayState, issuer);
        try {
            authnRequestRepository.save(authnRequestModel);
        } catch (DataIntegrityViolationException e) {
            // try second time if the first fails
            LOGGER.warn("Created ID already exists, try to get new one.", e);

            authnRequestModel = new AuthnRequestModel(username, relayState, issuer);
            try {
                authnRequestRepository.save(authnRequestModel);
            } catch (DataIntegrityViolationException ex) {
                // if the second also fails return null
                LOGGER.error("Created ID already exists. Stop now!", ex);

                return null;
            }
        }

        return authnRequestModel;
    }

    /**
     * delete old challenges stored in the database
     * challenges just have limited valid range
     *
     * @param now the Date, everything with notValidAfter before this will be deleted
     * @return true
     */
    public boolean deleteAllOldAuthnRequest(Date now) {
        LOGGER.info("Delete all old AuthnRequests.");
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("All being before: {}", LogEncoderHelper.encodeLogEntry(now.toString()));
        }

        Iterable<AuthnRequestModel> authnRequestModelIterable = authnRequestRepository
                .findAuthnRequestsByNotValidAfterIsBefore(now);

        for (AuthnRequestModel authnRequestModel : authnRequestModelIterable) {
            LOGGER.info("AuthnRequest with ID {} was old and so deleted", authnRequestModel.getId());
            authnRequestRepository.delete(authnRequestModel);
        }
        return true;
    }
}
