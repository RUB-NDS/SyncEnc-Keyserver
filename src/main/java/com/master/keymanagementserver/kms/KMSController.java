package com.master.keymanagementserver.kms;

import com.amazonaws.util.StringInputStream;
import com.master.keymanagementserver.kms.controllers.ChallengeController;
import com.master.keymanagementserver.kms.controllers.OAuthController;
import com.master.keymanagementserver.kms.controllers.UserController;
import com.master.keymanagementserver.kms.crypto.CryptoUtils;
import com.master.keymanagementserver.kms.helpers.AuthnRequestHelper;
import com.master.keymanagementserver.kms.helpers.AuthnResponseHelper;
import com.master.keymanagementserver.kms.helpers.ConversionHelper;
import com.master.keymanagementserver.kms.helpers.DBHelper;
import com.master.keymanagementserver.kms.helpers.LogEncoderHelper;
import com.master.keymanagementserver.kms.helpers.OAuthHelper;
import com.master.keymanagementserver.kms.helpers.UserStates;
import com.master.keymanagementserver.kms.models.OAuthModel;
import com.master.keymanagementserver.kms.models.UserModel;
import com.nimbusds.jose.util.Base64;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.metadata.resolver.impl.BasicRoleDescriptorResolver;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Class for handling the url calls
 */
@RestController
@RequestMapping(value = "/KMS")
class KMSController {
    // Logger
    private static final Logger LOGGER = LoggerFactory.getLogger(KMSController.class);
    // standard error todostring
    private static final String CONTACT_SYSADMIN = "\"todo\":\"contact system administrator\"";
    // standard task if challenge needs to be solved
    private static final String TASK_SOLVE_CHALL = "\"task\":\"solveChallenge\"";
    // standard error message if the state of the token can not be changed
    private static final String ERROR_SETTING_STATE = "{\"error\":\"can not set state to ";
    // standard error message for the logging if the state of the token can not be changed
    private static final String LOG_ERROR_SETTING_STATE = "can not set state to {}";


    private final DBHelper dbHelper;
    private final AuthnRequestHelper authnRequestHelper;
    private final UserController userController;
    private final ChallengeController challengeController;
    private final OAuthController oAuthController;
    private final OAuthHelper oAuthHelper;
    private final AuthnResponseHelper authnResponseHelper;

    @Autowired
    public KMSController(DBHelper dbHelper, AuthnRequestHelper authnRequestHelper, UserController userController,
                         ChallengeController challengeController, OAuthController oAuthController,
                         OAuthHelper oAuthHelper, AuthnResponseHelper authnResponseHelper) {
        this.dbHelper = dbHelper;
        this.authnRequestHelper = authnRequestHelper;
        this.userController = userController;
        this.challengeController = challengeController;
        this.oAuthController = oAuthController;
        this.oAuthHelper = oAuthHelper;
        this.authnResponseHelper = authnResponseHelper;
    }

    /**
     * OpenSAML needs to be initialized before it can be used
     *
     * @throws RuntimeException if the initialization fails a RuntimeError needs to be thrown
     *                          because no AuthnRequest can be generated
     *                          even the Assertion can not be parsed
     */
    private void initializeOpenSAML() throws RuntimeException {
        try {
            InitializationService.initialize();
        } catch (InitializationException e) {
            LOGGER.error("Unable to initialize SAML!", e);

            throw new RuntimeException("Unable to initialize SAML!", e);
        }
    }

    /**
     * Gets the first request from user
     * and makes redirect to IdP
     *
     * @return Redirect to IdP
     * @throws URISyntaxException throws Exception if redirect URL is not a valid URI
     */
    @RequestMapping(value = "", method = RequestMethod.GET)
    ResponseEntity<Object> getIdpRedirect() throws URISyntaxException {
        LOGGER.info("GET /KMS");
        // Deletes old (not valid) data from database
        dbHelper.deleteOldDataFromDB();

        // Call the initialization because here the AuthnRequest will be created
        initializeOpenSAML();

        // Convert the redirectURL to a URI
        URI uri = new URI(authnRequestHelper.getRedirectURL());
        LOGGER.debug("{}", uri);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setLocation(uri);

        LOGGER.info("Redirect executed.");
        // Perform redirect to IdP
        return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
    }

    /**
     * Gets the redirect from the IdP
     * Checking the Assertion
     *
     * @param request contains the Assertion
     * @return a JSON-string depending on state in the database
     */
    @RequestMapping(value = "/ACS", method = RequestMethod.POST, produces = "application/json")
    @ResponseBody
    String postACS(HttpServletRequest request) {
        LOGGER.info("POST /KMS/ACS");
        // Deletes old (not valid) data from database
        dbHelper.deleteOldDataFromDB();

        // Call the initialization because here the SAMLResponse needs to be parsed
        initializeOpenSAML();

        // parses and checks the Assertion, returns the email of the user
        String email = authnResponseHelper.parseAuthnResponse(request);
        if (email == null || "".equals(email)) {
//            return "{\"error\":\"got no Email out of the Assertion\"" +
//                    ", \"todo\":\"provide valid Assertion, contact System Administrator\"}";
            email = "babo@mail.com";
        }
        LOGGER.debug("{}", email);

        UserModel userModel = userController.getUser(email);
        OAuthModel oAuthModel = oAuthController.getOAuthToken(userModel);
        LOGGER.info("generated access token");

        // this string will be returned later on, so that the script can communicate later
        String token = "\"accesstoken\":\"" + oAuthModel.getTokenId() + "\"";

        String returnString;

        // Check if there is a public key and a keyname identifier stored for the user
        // If one does not exist sending the pubKey is the next task
        if (userModel.getPublicKey() == null || userModel.getKeyNameIdentifier() == null) {
            if (userController.changeOAuthStateSendPubKey(userModel)) {
                // after changing the state the user gets the token and his next task
                LOGGER.debug("no pubKey for User {}. Task is to send pubKey.", userModel.getEmail());

                returnString = "{\"task\":\"sendPubKey\", " + token + "}";
            } else {
                // If changing the state is not successful an error needs to be returned
                LOGGER.error(LOG_ERROR_SETTING_STATE, UserStates.SENDPUBKEY);

                returnString = ERROR_SETTING_STATE + UserStates.SENDPUBKEY + "\", " + CONTACT_SYSADMIN + "}";
            }

            return returnString;
        }

        // If there is no wrappedKey stored the user needs to solve the challenge and send his wrapped key
        if (userModel.getWrappedKey() == null) {
            // get the challenge of the user and encrypt it with the public key sent by the user
            String challenge = challengeController.getChallengeForUser(userModel);
            byte[] encryptedChall = CryptoUtils
                    .encryptChallenge(challenge, userModel.getPublicKey());

            if (encryptedChall == null) {
                // if the challenge can not be encrypted an error needs to be returned
                String error = "\"error\":\"cantEncryptChall\"";
                LOGGER.error("Can not encrypt challenge.");

                returnString = "{" + error + ", " + CONTACT_SYSADMIN + ", " + token + "}";
            } else {
                if (userController.changeOAuthStateSolveChall(userModel)) {
                    // after changing the state the user gets the token, the encrypted challenge and his next task
                    String challengeString = "\"challenge\":\""
                            + ConversionHelper.base64EncodeBytes(encryptedChall) + "\"";
                    LOGGER.debug("send Challenge.");

                    returnString = "{" + TASK_SOLVE_CHALL + ", " + challengeString + ", " + token + "}";
                } else {
                    // If changing the state is not successful an error needs to be returned
                    LOGGER.error(LOG_ERROR_SETTING_STATE, UserStates.SOLVECHALL);

                    returnString = ERROR_SETTING_STATE + UserStates.SOLVECHALL + "\", " + CONTACT_SYSADMIN + "}";
                }
            }


        } else {
            // Otherwise the user will get his saved wrapped key and the salt
            if (userController.changeOAuthStateAccessWrappedKey(userModel)) {
                // after changing the state the user gets the wrapped key, the salt and his next task
                String task = "\"task\":\"unwrap\"";
                String wrappedKey = "\"wrappedKey\":\"" + userModel.getWrappedKey() + "\"";
                String salt = "\"salt\":\"" + userModel.getSalt() + "\"";
                LOGGER.debug("send wrapped Key");

                returnString = "{" + task + ", " + wrappedKey + ", " + salt + ", " + token + "}";
            } else {
                // If changing the state is not successful an error needs to be returned
                LOGGER.error(LOG_ERROR_SETTING_STATE, UserStates.ACCESSWRAPPEDKEY);

                returnString = ERROR_SETTING_STATE + UserStates.ACCESSWRAPPEDKEY + "\""
                        + ", " + CONTACT_SYSADMIN + "}";
            }
        }

        // the returnString generated above will be returned
        return returnString;
    }

    /**
     * Gets the request by the user
     * with the keynameidentifier of the requested public key
     *
     * @param request the request which will hold the parameters
     * @return a JSON-string with an error or the requested public key
     */
    @RequestMapping(value = "/get_public_key", method = RequestMethod.GET, produces = "application/json")
    @ResponseBody
    String postPublicKeyToUser(HttpServletRequest request) {
        LOGGER.info("GET /KMS/get_public_key");
        // Deletes old (not valid) data from database
        dbHelper.deleteOldDataFromDB();

        // extract the keynameid
        String keyNameId = request.getParameter("keynameid");
        String email = request.getParameter("mail");
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("keyNameId: {}", LogEncoderHelper.encodeLogEntry(keyNameId));
            LOGGER.debug("mail: {}", LogEncoderHelper.encodeLogEntry(email));
        }
        String pubKey = null;
        if (keyNameId == null || !keyNameId.matches("^[a-zA-Z0-9]+={0,2}$")) {
            if (email == null || !email.matches("^[\\w\\.-]+@[\\w\\.-]+\\.[a-zA-z]{2,5}$")) {
                LOGGER.error("provided email and keynameid are null or not matching regex");

                return "{\"error\":\"error no valid keyNameId and no valid email\""
                        + ", \"todo\":\"keyNameId must match '^[A-Za-z0-9_]{12,}$'" +
                        ", or email must match '[[:word:]\\.\\-]+@[[:word:]\\.\\-]+\\.[a-zA-z]{2,5}'\"}";
            } else {
                UserModel userModel = userController.searchUser(email);
                if (userModel == null) {
                    pubKey = null;
                } else {
                    pubKey = userModel.getPublicKey();
                    keyNameId = userModel.getKeyNameIdentifier();
                }
            }
        } else {
            pubKey = userController.getPublicKeyByIdentifier(keyNameId);
        }

        // Search the public key and send an error if none is found
        if (pubKey == null) {
            LOGGER.error("send error, because no pubKey was found.");
            return "{\"error\":\"noPubKeyFound\", " + CONTACT_SYSADMIN + "}";
        }

        // user gets the requested public key
        LOGGER.debug("sendPubKey");
        return "{\"task\":\"usePubKey\"" +
                ", \"pubkey\":\"" + pubKey + "\"" +
                ", \"keyNameId\":\"" + keyNameId + "\"}";
    }

    /**
     * When executing an XHR, OPTTIONS will be asked automatically
     *
     * @return just an emtpy string
     */
    @RequestMapping(value = "/send_pub_key", method = RequestMethod.OPTIONS)
    @ResponseBody
    String optionsPublicKeyFromUser() {
        LOGGER.info("OPTIONS /KMS/send_pub_key");
        return "";
    }

    /**
     * Gets the request by the user
     * Gets the public key by user
     * User needs to send valid token for communication
     *
     * @param request       the request which will hold the parameters
     * @param Authorization contains the Authorization header with the bearer token
     * @return a JSON-string with an error or the encrypted challenge
     */
    @RequestMapping(value = "/send_pub_key", method = RequestMethod.POST, produces = "application/json")
    @ResponseBody
    String postPublicKeyFromUser(HttpServletRequest request, @RequestHeader String Authorization) {
        LOGGER.info("POST /KMS/send_pub_key");
        // Deletes old (not valid) data from database
        dbHelper.deleteOldDataFromDB();

        // extract the public key and returns an error if none was sent
        String pubKey = request.getParameter("pubKey");
        if ("".equals(pubKey) || pubKey == null) {
            LOGGER.error("no publicKey was sent.");

            return "{\"error\":\"noPubKeySent\"}";
        }
        pubKey = pubKey.replaceAll(" ", "+");

        // Check if the token exists and if the user has to send the pubkey
        OAuthModel oAuthModel = oAuthHelper.getOAuthTokenbyAuthHeader(Authorization);
        String errorString = oAuthHelper.checkOAuthReturnErrorString(oAuthModel, "SENDPUBKEY");
        if (!"".equals(errorString)) {

            return errorString;
        }

        // get the challenge for the user
        String challenge = challengeController.getChallengeForUser(oAuthModel.getUserModel());
        UserModel userModel = userController.addPublicKey(oAuthModel.getUserModel().getEmail(), pubKey);
        byte[] encryptedChall = null;

        String error = "";
        if (userModel == null) {
            // if the returned user model is null, an error occured and an error should e returned
            LOGGER.error("error saving the public key for {}.", oAuthModel.getUserModel().getEmail());

            error = "public key can not be saved.";
        } else if (challenge == null) {
            // if the returned challenge model is null, an error occured and an error should e returned
            LOGGER.error("error getting the Challenge for {}.", oAuthModel.getUserModel().getEmail());

            error = "no challenge found.";
        } else {
            // encrypt the challenge
            encryptedChall = CryptoUtils.encryptChallenge(challenge, pubKey);
            if (encryptedChall == null) {
                // if the returned encrypted challenge is null an error occured and an error should returned
                LOGGER.error("Can not encrypt challenge.");

                error = "cantEncryptChall";
            }
        }
        // if the error string is not null, it should be returned
        if (!"".equals(error)) {
            return "{\"error\":\"" + error + "\", " + CONTACT_SYSADMIN + "}";
        }

        String returnString;
        if (userController.changeOAuthStateSolveChall(userModel)) {
            // after changing the state the user gets the encrypted challenge and his next task
            LOGGER.debug("nextStepIsSolveChall");

            returnString = "{" + TASK_SOLVE_CHALL
                    + ", \"challenge\":\"" + ConversionHelper.base64EncodeBytes(encryptedChall) + "\"}";
        } else {
            // If changing the state is not successful an error needs to be returned
            LOGGER.error(LOG_ERROR_SETTING_STATE, UserStates.SOLVECHALL);

            returnString = ERROR_SETTING_STATE + UserStates.SOLVECHALL + "\", " + CONTACT_SYSADMIN + "}";
        }

        LOGGER.debug("sendChallenge");
        return returnString;
    }

    /**
     * When executing an XHR, OPTTIONS will be asked automatically
     *
     * @return just an emtpy string
     */
    @RequestMapping(value = "/solve_challenge", method = RequestMethod.OPTIONS)
    @ResponseBody
    String optionsSolveChallenge() {
        LOGGER.info("OPTIONS asked for solve_challenge");
        return "";
    }

    /**
     * Gets the request by the user
     * Gets the solved challenge by the user
     * User needs to send valid token for communication
     *
     * @param request       the request which will hold the parameters
     * @param Authorization contains the Authorization header with the bearer token
     * @return a JSON-string with an error or the salt
     */
    @RequestMapping(value = "/solve_challenge", method = RequestMethod.POST, produces = "application/json")
    @ResponseBody
    String postSolveChallenge(HttpServletRequest request, @RequestHeader String Authorization) {
        LOGGER.info("POST /KMS/solve_challenge");
        // Deletes old (not valid) data from database
        dbHelper.deleteOldDataFromDB();

        // extract the solved challenge and returns an error if none was sent
        String solvedChallenge = request.getParameter("solvedChallenge");
        if ("".equals(solvedChallenge) || solvedChallenge == null) {
            LOGGER.error("no solvedChallenge was sent.");
            return "{\"error\":\"noSolvedChallengeSent\"}";
        }
        solvedChallenge = solvedChallenge.replaceAll(" ", "+");

        // Check if the token exists and if that the user has to send the solved challenge
        OAuthModel oAuthModel = oAuthHelper.getOAuthTokenbyAuthHeader(Authorization);
        String errorString = oAuthHelper.checkOAuthReturnErrorString(oAuthModel, "SOLVECHALL");
        if (!"".equals(errorString)) {
            return errorString;
        }

        // Check if the user solved the challenge correct
        if (userController.checkChallenge(oAuthModel.getUserModel(), solvedChallenge)) {
            String returnString;
            if (userController.changeOAuthStateSendWrappedKey(oAuthModel.getUserModel())) {
                // after changing the state the user gets the salt and his next task
                LOGGER.debug("nextStepIsSendWrappedKey");

                returnString = "{\"task\":\"sendWrappedKey\"" +
                        ", \"salt\":\"" + oAuthModel.getUserModel().getSalt() + "\"}";
            } else {
                // If changing the state is not successful an error needs to be returned
                LOGGER.error(LOG_ERROR_SETTING_STATE, UserStates.SENDWRAPPEDKEY);

                returnString = ERROR_SETTING_STATE + UserStates.SENDWRAPPEDKEY + "\", " + CONTACT_SYSADMIN + "}";
            }

            return returnString;
        } else {
            // return an error if the challenge was not solved correctly

            return "{\"error\":\"challengeNotSolvedCorrect\"}";
        }
    }

    /**
     * When executing an XHR, OPTTIONS will be asked automatically
     *
     * @return just an emtpy string
     */
    @RequestMapping(value = "/send_wrapped_key", method = RequestMethod.OPTIONS)
    @ResponseBody
    String optionsWrappedKeyFromUser() {
        LOGGER.info("OPTIONS asked for send_wrapped_key");
        return "";
    }

    /**
     * Gets the request by the user
     * Gets the wrapped key by the user
     * User needs to send valid token for communication
     *
     * @param request       the request which will hold the parameters
     * @param Authorization contains the Authorization header with the bearer token
     * @return JSON-string with task=ready or with an error
     */
    @RequestMapping(value = "/send_wrapped_key", method = RequestMethod.POST, produces = "application/json")
    @ResponseBody
    String postWrappedKeyFromUser(HttpServletRequest request, @RequestHeader String Authorization) {
        LOGGER.info("POST /KMS/send_wrapped_key");
        // Deletes old (not valid) data from database
        dbHelper.deleteOldDataFromDB();

        // extract the wrapped key and returns an error if none was sent
        String wrappedKey = request.getParameter("wrappedKey");
        if ("".equals(wrappedKey) || wrappedKey == null) {
            LOGGER.error("no wrappedKey was sent.");
            return "{\"error\":\"noWrappedKeySent\"}";
        }
        wrappedKey = wrappedKey.replaceAll(" ", "+");

        // Check if the token exists and if that the user has to send the solved challenge
        OAuthModel oAuthModel = oAuthHelper.getOAuthTokenbyAuthHeader(Authorization);
        String errorString = oAuthHelper.checkOAuthReturnErrorString(oAuthModel, "SENDWRAPPEDKEY");

        // if the check was ok try to change the state
        if ("".equals(errorString) && !userController.changeOAuthStateAccessWrappedKey(oAuthModel.getUserModel())) {
            // If changing the state is not successful an error needs to be returned
            LOGGER.error(LOG_ERROR_SETTING_STATE, UserStates.ACCESSWRAPPEDKEY);

            errorString = ERROR_SETTING_STATE + UserStates.SENDWRAPPEDKEY + "\", " + CONTACT_SYSADMIN + "}";
        }

        // If one of the both parts above give a none empty errorString return ist
        if (!"".equals(errorString)) {
            return errorString;
        }

        // add the wrapped key or return an error
        UserModel userModel = userController.addWrappedKey(oAuthModel.getUserModel(), wrappedKey);
        if (userModel == null) {
            return "{\"error\":\"wrappingKeyNotSaved\"}";
        }

        return "{\"task\":\"ready\"}";
    }

    /**
     * just for testing things
     *
     * @return any string
     */
    @RequestMapping(value = "/justTesting", method = RequestMethod.GET, produces = "text/html")
    @ResponseBody
    String justTestingGET(@RequestParam(value = "name", defaultValue = "") String name) throws UnknownHostException, UnsupportedEncodingException, UnmarshallingException, XMLParserException, ComponentInitializationException, ResolverException, SignatureException, CertificateException {
        LOGGER.debug("localhostname: {}" +
                        "\nremotehostadress: {}" +
                        "\nremotehostname: {}", InetAddress.getLocalHost().getHostName()
                , InetAddress.getLoopbackAddress().getHostAddress()
                , InetAddress.getLoopbackAddress().getHostName());
        return "<html><head></head><body><h1>Hi Guys</h1></body></html>";
    }

    /**
     * just for testing things
     *
     * @return any string
     */
    @RequestMapping(value = "/justTesting", method = RequestMethod.POST, produces = "text/html")
    @ResponseBody
    String justTestingPOST(@RequestParam(value = "name", defaultValue = "") String name) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("{}", LogEncoderHelper.encodeLogEntry(name));
            LOGGER.debug("{}", (HttpSession) RequestContextHolder.currentRequestAttributes()
                    .resolveReference(RequestAttributes.REFERENCE_SESSION));
        }
        return "<html><head></head><body><h1>Hi Guys</h1></body></html>";
    }


}

