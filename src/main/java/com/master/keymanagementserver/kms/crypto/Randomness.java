package com.master.keymanagementserver.kms.crypto;

import com.master.keymanagementserver.kms.helpers.ConversionHelper;
import com.master.keymanagementserver.kms.helpers.LogEncoderHelper;
import com.nimbusds.jose.util.Base64;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * provides functions for generating randomness
 */
@Component
public class Randomness {
    private static final Logger LOGGER = LoggerFactory.getLogger(Randomness.class);

    @Autowired
    public Randomness() {
    }

    /**
     * generates random bytes
     *
     * @param length determines the number of bytes
     * @return byte array with generated random bytes
     */
    public byte[] generateRandomBytes(Integer length) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("Generate {} random bytes."
                    , LogEncoderHelper.encodeLogEntry(length.toString()));
        }
        // getInstanceStrong sollte nicht genutzt werden, da /dev/random  genutzt wird
        SecureRandom secureRandom = new SecureRandom();

        // Auf diese Weise wird zufälliger Seed erstellt
        secureRandom.setSeed(secureRandom.generateSeed(128));

        byte[] data = new byte[length];
        secureRandom.nextBytes(data);

        return data;
    }

    /**
     * generates a token containing the actual DateTime
     * useful for tokens that does not have to be unguessable
     *
     * @param input      will be included in the token
     * @param randLength length of random bytes included in the token
     * @return base64 encoded token string
     */
    public String generateTokenWithDate(String input, Integer randLength) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("generate Token with date included.");
        }

        String random = ConversionHelper.bytesToHex(generateRandomBytes(randLength));
        String keySource = input + (new DateTime()) + random;
        Base64 base64 = ConversionHelper.base64EncodeBytes(keySource.getBytes(StandardCharsets.UTF_8));

        return base64.toString();
    }

    /**
     * generates a token containing the actual DateTime
     * useful for tokens that have to be unguessable
     *
     * @param input      will be included in the token
     * @param randLength length of random bytes included in the token
     * @return base64 encoded string
     */
    public String generateTokenWithoutDate(String input, Integer randLength) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("generate TOken without date included");
        }

        String random = ConversionHelper.bytesToHex(generateRandomBytes(randLength));
        String keySource = input + random;
        Base64 base64 = ConversionHelper.base64EncodeBytes(keySource.getBytes(StandardCharsets.UTF_8));

        return base64.toString();
    }
}
