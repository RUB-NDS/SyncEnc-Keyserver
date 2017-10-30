package com.master.keymanagementserver.kms.crypto;

import com.master.keymanagementserver.kms.helpers.ConversionHelper;
import com.master.keymanagementserver.kms.helpers.LogEncoderHelper;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import sun.rmi.runtime.Log;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.text.ParseException;
import java.util.EnumSet;
import java.util.Set;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * provides functions for crypto
 */
@Component
public class CryptoUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoUtils.class);
    private static final String CRYPT_VERFAHREN = "RSA/None/OAEPWithSHA-256AndMGF1Padding";

    @Autowired
    public CryptoUtils() {
    }

    /**
     * generate RSA key with the provided base64 encoded string
     *
     * @param pubKey string containing the data needed for generating the pubKey
     * @return the generated public key, null if error occurred
     */
    static PublicKey generatePublicKeyOutOfPubKeyString(String pubKey) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("generate public key out of the string {}"
                    , LogEncoderHelper.encodeLogEntry(pubKey));
        }
        String decodedPubKey = ConversionHelper.base64DecodeToString(new Base64(pubKey));
        try {
            // parse the decoded string (JWK) and get data out of the JSON Object
            JSONObject jsonObject = JSONObjectUtils.parse(decodedPubKey);
            Base64URL n = new Base64URL(jsonObject.getAsString("n"));
            Base64URL e = new Base64URL(jsonObject.getAsString("e"));
            Algorithm algo = new Algorithm(jsonObject.getAsString("alg"));
            KeyUse keyUse = KeyUse.ENCRYPTION;
            Set<KeyOperation> ops = EnumSet.of(KeyOperation.ENCRYPT);
            if(LOGGER.isDebugEnabled()){
                LOGGER.debug("with modulus {} and public exponent {}"
                        , LogEncoderHelper.encodeLogEntry(n.decodeToString())
                        , LogEncoderHelper.encodeLogEntry(e.decodeToString()));
            }

            // Generate RSA pubKey provided by collected data
            RSAKey jwk = new RSAKey(n, e, keyUse, ops, algo, null, null, null, null, null, null);

            return jwk.toPublicKey();
        } catch (ParseException | JOSEException e) {
            LOGGER.error("Can not generate the public key with the given String.", e);

            return null;
        }
    }

    /**
     * encrypt the provided challenge with the pubKey generated out of the provided pubKey string
     *
     * @param challenge challenge that needs to be encrypted
     * @param pubKey    string of the decoded JWK
     * @return byte-array of the encrypted challenge, null if error occurred
     */
    public static byte[] encryptChallenge(String challenge, String pubKey) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("encrypt the challenge {} with the pubKeyString {}"
                    , LogEncoderHelper.encodeLogEntry(challenge)
                    , LogEncoderHelper.encodeLogEntry(pubKey));
        }
        try {
            PublicKey publicKey = generatePublicKeyOutOfPubKeyString(pubKey);
            if (publicKey == null) {
                return null;
            }
            if(LOGGER.isDebugEnabled()){
                LOGGER.debug("Add Bouncy Castle Provider");
            }
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance(CRYPT_VERFAHREN);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] challBytes = ConversionHelper.base64DecodeToBytes(new Base64(challenge));
            if(LOGGER.isDebugEnabled()){
                LOGGER.debug("return encrypted challenge");
            }
            return cipher.doFinal(challBytes);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            LOGGER.error("Unable to encrypt the ChallengeBytes with the pubKey.", e);

            return null;
        }
    }

    /**
     * hash the provided input with sha-512
     *
     * @param input the input needs to be hashed
     * @return the hashed string
     */
    public String hashInput(String input) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("hash the input {}"
                    , LogEncoderHelper.encodeLogEntry(input));
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] hashedBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));

            if(LOGGER.isDebugEnabled()){
                LOGGER.debug("build a string from the hash");
            }
            StringBuilder sb = new StringBuilder();
            for (byte hashedByte : hashedBytes) {
                sb.append(Integer.toString((hashedByte & 0xff) + 0x100, 16).substring(1));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Could not hash the input. {}", e);

            return null;
        }
    }
}
