package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class EncryptorUtils {
    public static final String EMPTY_PASSWORD_PROVIDED_S = "Empty Password provided %s";
    public static final String DATA_TO_BE_DECRYPTED_IS_EMPTY_S = "Data to be decrypted is Empty %s";

    public static String decrypt(String password, String encryptedData) {
        String decryptedData = "./tmp123";
        if (StringUtils.isBlank(password)){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(EMPTY_PASSWORD_PROVIDED_S, password), EncryptorUtils.class.getName());
            return null;
        }
        if (StringUtils.isBlank(encryptedData)){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(DATA_TO_BE_DECRYPTED_IS_EMPTY_S, encryptedData), EncryptorUtils.class.getName());
            return null;
        }
        return decryptedData;
    }

    public static boolean verifyHashData(String knownDecryptedDataHash, String decryptedData) {
        return StringUtils.equals(getSHA256HexDigest(decryptedData), knownDecryptedDataHash);
    }
    private static String getSHA256HexDigest(String data) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            digest.update(data.getBytes());
            byte[] hashedBytes = digest.digest();
            return convertByteArrayToHexString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
    private static String convertByteArrayToHexString(byte[] arrayBytes) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < arrayBytes.length; i++) {
            String hex = Integer.toHexString(0xFF & arrayBytes[i]);
            if (hex.length() == 1) {
                stringBuffer.append('0');
            }
            stringBuffer.append(hex);
        }
        return stringBuffer.toString();
    }

}
