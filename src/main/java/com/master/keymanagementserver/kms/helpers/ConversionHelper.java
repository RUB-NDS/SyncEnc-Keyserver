package com.master.keymanagementserver.kms.helpers;

import com.nimbusds.jose.util.Base64;

import java.nio.charset.StandardCharsets;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

public final class ConversionHelper {

    private ConversionHelper() {
    }

    public static String bytesToHex(byte[] bytes) {
        HexBinaryAdapter adapter = new HexBinaryAdapter();

        return adapter.marshal(bytes);
    }

    static byte[] hexToBytes(String hexString) {
        HexBinaryAdapter adapter = new HexBinaryAdapter();

        return adapter.unmarshal(hexString);
    }

    public static Base64 base64EncodeBytes(byte[] bytes) {
        return Base64.encode(bytes);
    }

    public static Base64 base64EncodeString(String string) {
        return Base64.encode(string.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] base64DecodeToBytes(Base64 base64) {
        return base64.decode();
    }

    public static String base64DecodeToString(Base64 base64) {
        return base64.decodeToString();
    }


}
