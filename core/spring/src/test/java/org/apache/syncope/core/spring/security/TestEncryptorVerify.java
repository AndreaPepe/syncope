package org.apache.syncope.core.spring.security;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.ApplicationContextProvider;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.MockedStatic;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;


@RunWith(Parameterized.class)
public class TestEncryptorVerify extends TestEncryptorBaseClass{
    private Encryptor encryptor;
    private String value;
    private CipherAlgorithm cipherAlgorithm;
    private String encoded;
    private boolean encodedCorrectly;

    public static MockedStatic<ApplicationContextProvider> appCtxProviderMocked;

    public TestEncryptorVerify(String value, CipherAlgorithm cipherAlgorithm, boolean encodedCorrectly) {
        configure(value, cipherAlgorithm, encodedCorrectly);
    }

    private void configure(String value, CipherAlgorithm cipherAlgorithm, boolean encodedCorrectly) {
        // instance under test
        if (encryptor == null)
            encryptor = Encryptor.getInstance();
        this.value = value;
        this.cipherAlgorithm = cipherAlgorithm;
        this.encodedCorrectly = encodedCorrectly;
        if (encodedCorrectly) {
            try {
                this.encoded = encryptor.encode(value, cipherAlgorithm);
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
            }
        } else {
            this.encoded = "randomCrap";
        }
    }

    @Parameterized.Parameters
    public static Collection<Object[]> parameters() {
        String emptyString = "";
        String stringSmallerThanBlock = buildString(2);
        String stringBiggerThanBlock = buildString(129);


        return Arrays.asList(new Object[][]{
                {null, CipherAlgorithm.SHA, true},
                {emptyString, CipherAlgorithm.SHA, true},
                {stringSmallerThanBlock, CipherAlgorithm.SHA, true},
                {stringBiggerThanBlock, CipherAlgorithm.SHA, true},
                {null, CipherAlgorithm.SHA, false},
                {emptyString, CipherAlgorithm.SHA, false},
                {stringSmallerThanBlock, CipherAlgorithm.SHA, false},
                {stringBiggerThanBlock, CipherAlgorithm.SHA, false},
                {null, CipherAlgorithm.SHA1, true},
                {emptyString, CipherAlgorithm.SHA1, true},
                {stringSmallerThanBlock, CipherAlgorithm.SHA1, true},
                {stringBiggerThanBlock, CipherAlgorithm.SHA1, true},
                {null, CipherAlgorithm.SHA1, false},
                {emptyString, CipherAlgorithm.SHA1, false},
                {stringSmallerThanBlock, CipherAlgorithm.SHA1, false},
                {stringBiggerThanBlock, CipherAlgorithm.SHA1, false},
                {null, CipherAlgorithm.SHA256, true},
                {emptyString, CipherAlgorithm.SHA256, true},
                {stringSmallerThanBlock, CipherAlgorithm.SHA256, true},
                {stringBiggerThanBlock, CipherAlgorithm.SHA256, true},
                {null, CipherAlgorithm.SHA256, false},
                {emptyString, CipherAlgorithm.SHA256, false},
                {stringSmallerThanBlock, CipherAlgorithm.SHA256, false},
                {stringBiggerThanBlock, CipherAlgorithm.SHA256, false},
                {null, CipherAlgorithm.SHA512, true},
                {emptyString, CipherAlgorithm.SHA512, true},
                {stringSmallerThanBlock, CipherAlgorithm.SHA512, true},
                {stringBiggerThanBlock, CipherAlgorithm.SHA512, true},
                {null, CipherAlgorithm.SHA512, false},
                {emptyString, CipherAlgorithm.SHA512, false},
                {stringSmallerThanBlock, CipherAlgorithm.SHA512, false},
                {stringBiggerThanBlock, CipherAlgorithm.SHA512, false},
                {null, CipherAlgorithm.AES, true},
                {emptyString, CipherAlgorithm.AES, true},
                {stringSmallerThanBlock, CipherAlgorithm.AES, true},
                {stringBiggerThanBlock, CipherAlgorithm.AES, true},
                {null, CipherAlgorithm.AES, false},
                {emptyString, CipherAlgorithm.AES, false},
                {stringSmallerThanBlock, CipherAlgorithm.AES, false},
                {stringBiggerThanBlock, CipherAlgorithm.AES, false},
                {null, CipherAlgorithm.SMD5, true},
                {emptyString, CipherAlgorithm.SMD5, true},
                {stringSmallerThanBlock, CipherAlgorithm.SMD5, true},
                {stringBiggerThanBlock, CipherAlgorithm.SMD5, true},
                {null, CipherAlgorithm.SMD5, false},
                {emptyString, CipherAlgorithm.SMD5, false},
                {stringSmallerThanBlock, CipherAlgorithm.SMD5, false},
                {stringBiggerThanBlock, CipherAlgorithm.SMD5, false},
                {null, CipherAlgorithm.SSHA, true},
                {emptyString, CipherAlgorithm.SSHA, true},
                {stringSmallerThanBlock, CipherAlgorithm.SSHA, true},
                {stringBiggerThanBlock, CipherAlgorithm.SSHA, true},
                {null, CipherAlgorithm.SSHA, false},
                {emptyString, CipherAlgorithm.SSHA, false},
                {stringSmallerThanBlock, CipherAlgorithm.SSHA, false},
                {stringBiggerThanBlock, CipherAlgorithm.SSHA, false},
                {null, CipherAlgorithm.SSHA1, true},
                {emptyString, CipherAlgorithm.SSHA1, true},
                {stringSmallerThanBlock, CipherAlgorithm.SSHA1, true},
                {stringBiggerThanBlock, CipherAlgorithm.SSHA1, true},
                {null, CipherAlgorithm.SSHA1, false},
                {emptyString, CipherAlgorithm.SSHA1, false},
                {stringSmallerThanBlock, CipherAlgorithm.SSHA1, false},
                {stringBiggerThanBlock, CipherAlgorithm.SSHA1, false},
                {null, CipherAlgorithm.SSHA256, true},
                {emptyString, CipherAlgorithm.SSHA256, true},
                {stringSmallerThanBlock, CipherAlgorithm.SSHA256, true},
                {stringBiggerThanBlock, CipherAlgorithm.SSHA256, true},
                {null, CipherAlgorithm.SSHA256, false},
                {emptyString, CipherAlgorithm.SSHA256, false},
                {stringSmallerThanBlock, CipherAlgorithm.SSHA256, false},
                {stringBiggerThanBlock, CipherAlgorithm.SSHA256, false},
                {null, CipherAlgorithm.SSHA512, true},
                {emptyString, CipherAlgorithm.SSHA512, true},
                {stringSmallerThanBlock, CipherAlgorithm.SSHA512, true},
                {stringBiggerThanBlock, CipherAlgorithm.SSHA512, true},
                {null, CipherAlgorithm.SSHA512, false},
                {emptyString, CipherAlgorithm.SSHA512, false},
                {stringSmallerThanBlock, CipherAlgorithm.SSHA512, false},
                {stringBiggerThanBlock, CipherAlgorithm.SSHA512, false},
                {null, CipherAlgorithm.BCRYPT, true},
                {emptyString, CipherAlgorithm.BCRYPT, true},
                {stringSmallerThanBlock, CipherAlgorithm.BCRYPT, true},
                {stringBiggerThanBlock, CipherAlgorithm.BCRYPT, true},
                {null, CipherAlgorithm.BCRYPT, false},
                {emptyString, CipherAlgorithm.BCRYPT, false},
                {stringSmallerThanBlock, CipherAlgorithm.BCRYPT, false},
                {stringBiggerThanBlock, CipherAlgorithm.BCRYPT, false},
                {null, null, true},
                {emptyString, null, true},
                {stringSmallerThanBlock, null, true},
                {stringBiggerThanBlock, null, true},
                {null, null, false},
                {emptyString, null, false},
                {stringSmallerThanBlock, null, false},
                {stringBiggerThanBlock, null, false}
        });
    }

    private static String buildString(int numChars) {
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < numChars; i++) {
            builder.append(alphabet.charAt(i % alphabet.length()));
        }
        return builder.toString();
    }


    @Test
    public void testVerify() {
        boolean expectedResult;

        if (value == null)
            expectedResult = false;
        else
            expectedResult = encodedCorrectly;

        boolean result = encryptor.verify(value, cipherAlgorithm, encoded);
        Assert.assertEquals(expectedResult, result);
    }
}
