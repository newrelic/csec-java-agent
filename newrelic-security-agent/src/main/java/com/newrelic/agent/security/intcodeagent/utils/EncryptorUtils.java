package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.instrumentator.utils.CallbackUtils;
import com.newrelic.agent.security.instrumentator.utils.HashGenerator;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.Agent;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

public class EncryptorUtils {
    public static final String PBKDF_2_WITH_HMAC_SHA_1 = "PBKDF2WithHmacSHA1";
    public static final String AES_CBC_PKCS_5_PADDING = "AES/CBC/PKCS5Padding";
    public static final String AES = "AES";
    private static final int ITERATION = 1024;
    private static final int KEY_LEN = 256;
    private static final int OFFSET = 16;
    private static final String ERROR_WHILE_GENERATING_REQUIRED_SALT_FROM_S_S = "Error while generating required salt from %s : %s";
    private static final String ERROR_WHILE_DECRYPTION = "Error while decryption %s : %s ";
    private static final String ENCRYPTED_DATA_S_DECRYPTED_DATA_S = "Encrypted Data : %s , Decrypted data %s ";
    public static final String INCORRECT_SECRET_PROVIDED_S_S = "Incorrect Password / salt provided : %s";
    public static final String EMPTY_PASSWORD_PROVIDED_S = "Empty Password provided %s";
    public static final String DATA_TO_BE_DECRYPTED_IS_EMPTY_S = "Data to be decrypted is Empty %s";

    private static Cipher cipher = null;

    private static void prepareCipherInstance(String password) throws Exception {
        if (Agent.isDebugEnabled()) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, "Debug: Preparing Cipher instance for decrypting data", EncryptorUtils.class.getName());
        }
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF_2_WITH_HMAC_SHA_1);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), generateSalt(password), ITERATION, KEY_LEN);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), AES);
        cipher = Cipher.getInstance(AES_CBC_PKCS_5_PADDING);
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[OFFSET];
        secureRandom.nextBytes(iv);
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
    }

    public static String decrypt(String password, String encryptedData) {
        String decryptedData;
        if (StringUtils.isBlank(password)){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(EMPTY_PASSWORD_PROVIDED_S, password), EncryptorUtils.class.getName());
            return null;
        }
        if (StringUtils.isBlank(encryptedData)){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(DATA_TO_BE_DECRYPTED_IS_EMPTY_S, encryptedData), EncryptorUtils.class.getName());
            return null;
        }
        try {
            if (cipher == null) {
                prepareCipherInstance(password);
            }
            // Decrypt the content
            byte[] decryptedBytes = cipher.doFinal(Hex.decodeHex(encryptedData));
            decryptedData = new String(decryptedBytes, OFFSET, decryptedBytes.length - OFFSET);
            if (Agent.isDebugEnabled()) {
                NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format("Debug: Decrypted data for encrypted data %s is : %s", encryptedData, decryptedData), EncryptorUtils.class.getName());
            }
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(ENCRYPTED_DATA_S_DECRYPTED_DATA_S, encryptedData, decryptedData), EncryptorUtils.class.getName());
            return decryptedData;
        } catch (DecoderException ignored) {

        } catch (InvalidAlgorithmParameterException e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(INCORRECT_SECRET_PROVIDED_S_S, e.getMessage()), EncryptorUtils.class.getName());
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(ERROR_WHILE_DECRYPTION, encryptedData, e.getMessage()), EncryptorUtils.class.getName());
        }
        return null;
    }

    public static boolean verifyHashData(String knownDecryptedDataHash, String decryptedData) {
        if (StringUtils.isBlank(decryptedData)){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format("Decrypted Data is empty %s", decryptedData), EncryptorUtils.class.getName());
            return false;
        }
        if (StringUtils.isBlank(knownDecryptedDataHash)){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format("Known-Decrypted Data Hash is empty %s", knownDecryptedDataHash), EncryptorUtils.class.getName());
            return false;
        }
        if (Agent.isDebugEnabled() && !StringUtils.equals(HashGenerator.getSHA256HexDigest(decryptedData), knownDecryptedDataHash)) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format("Debug: The hash of the decrypted data for %s does not match.", decryptedData), EncryptorUtils.class.getName());
        }
        return StringUtils.equals(HashGenerator.getSHA256HexDigest(decryptedData), knownDecryptedDataHash);
    }

    private static byte[] generateSalt(String salt) throws DecoderException {
        try {
            return Hex.decodeHex(String.valueOf(Hex.encodeHex(StringUtils.left(salt, OFFSET).getBytes())));
        } catch (DecoderException e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(ERROR_WHILE_GENERATING_REQUIRED_SALT_FROM_S_S, salt, e.getMessage()), EncryptorUtils.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.WARNING, String.format(ERROR_WHILE_GENERATING_REQUIRED_SALT_FROM_S_S, salt, e.getMessage()), e, EncryptorUtils.class.getName());
            throw e;
        }
    }
}
