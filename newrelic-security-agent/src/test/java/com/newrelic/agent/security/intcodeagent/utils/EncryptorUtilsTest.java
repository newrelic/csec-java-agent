package com.newrelic.agent.security.intcodeagent.utils;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;

public class EncryptorUtilsTest {

    private final String hash = "0872effe487c8eb8681b0a627ce6f04c7a25bcd2a28834db42bdc40a52a85af1";
    private final String encryptedData = "7cabdd48937668fd9707ef727fb1a2213f70434d78955de81c9a35cd7a266efa";
    private final String password = "password";
    private final String file = "/tmp/test";


    @Test
    public void decryptTest() {
        Assert.assertNull(EncryptorUtils.decrypt("", ""));
        Assert.assertNull(EncryptorUtils.decrypt(password, ""));
        Assert.assertEquals(file, EncryptorUtils.decrypt(password, encryptedData));
        Assert.assertNull(EncryptorUtils.decrypt(password, hash));
    }

    @Test
    public void decryptFailTest() {
        Assert.assertNull(EncryptorUtils.decrypt(password, "123"));
    }

    @Test
    public void verifyHashDataTest() {
        Assert.assertFalse(EncryptorUtils.verifyHashData("", ""));
        Assert.assertFalse(EncryptorUtils.verifyHashData(password, ""));
        Assert.assertFalse(EncryptorUtils.verifyHashData(password, encryptedData));
        Assert.assertTrue(EncryptorUtils.verifyHashData(hash, file));
    }
}
