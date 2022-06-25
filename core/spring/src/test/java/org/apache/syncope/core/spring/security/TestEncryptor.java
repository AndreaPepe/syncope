package org.apache.syncope.core.spring.security;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class TestEncryptor extends TestEncryptorBaseClass {
    private Encryptor encryptor;
    private String stringToEncode;
    private CipherAlgorithm cipherAlgorithm;

    public TestEncryptor(String toBeEncoded, CipherAlgorithm cipherAlgorithm) {
        configure(toBeEncoded, cipherAlgorithm);
    }

    private void configure(String stringToEncode, CipherAlgorithm cipherAlgorithm) {
        // instance under test
        if (encryptor == null)
            encryptor = Encryptor.getInstance();
        this.stringToEncode = stringToEncode;
        this.cipherAlgorithm = cipherAlgorithm;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> parameters() {
        String emptyString = "";
        String stringSmallerThanBlock = buildString(2);
        String stringBiggerThanBlock = buildString(129);


        return Arrays.asList(new Object[][]{
                {null, CipherAlgorithm.SHA},
                {emptyString, CipherAlgorithm.SHA},
                {stringSmallerThanBlock, CipherAlgorithm.SHA},
                {stringBiggerThanBlock, CipherAlgorithm.SHA},
                {null, CipherAlgorithm.SHA1},
                {emptyString, CipherAlgorithm.SHA1},
                {stringSmallerThanBlock, CipherAlgorithm.SHA1},
                {stringBiggerThanBlock, CipherAlgorithm.SHA1},
                {null, CipherAlgorithm.SHA256},
                {emptyString, CipherAlgorithm.SHA256},
                {stringSmallerThanBlock, CipherAlgorithm.SHA256},
                {stringBiggerThanBlock, CipherAlgorithm.SHA256},
                {null, CipherAlgorithm.SHA512},
                {emptyString, CipherAlgorithm.SHA512},
                {stringSmallerThanBlock, CipherAlgorithm.SHA512},
                {stringBiggerThanBlock, CipherAlgorithm.SHA512},
                {null, CipherAlgorithm.AES},
                {emptyString, CipherAlgorithm.AES},
                {stringSmallerThanBlock, CipherAlgorithm.AES},
                {stringBiggerThanBlock, CipherAlgorithm.AES},
                {null, CipherAlgorithm.SMD5},
                {emptyString, CipherAlgorithm.SMD5},
                {stringSmallerThanBlock, CipherAlgorithm.SMD5},
                {stringBiggerThanBlock, CipherAlgorithm.SMD5},
                {null, CipherAlgorithm.SSHA},
                {emptyString, CipherAlgorithm.SSHA},
                {stringSmallerThanBlock, CipherAlgorithm.SSHA},
                {stringBiggerThanBlock, CipherAlgorithm.SSHA},
                {null, CipherAlgorithm.SSHA1},
                {emptyString, CipherAlgorithm.SSHA1},
                {stringSmallerThanBlock, CipherAlgorithm.SSHA1},
                {stringBiggerThanBlock, CipherAlgorithm.SSHA1},
                {null, CipherAlgorithm.SSHA256},
                {emptyString, CipherAlgorithm.SSHA256},
                {stringSmallerThanBlock, CipherAlgorithm.SSHA256},
                {stringBiggerThanBlock, CipherAlgorithm.SSHA256},
                {null, CipherAlgorithm.SSHA512},
                {emptyString, CipherAlgorithm.SSHA512},
                {stringSmallerThanBlock, CipherAlgorithm.SSHA512},
                {stringBiggerThanBlock, CipherAlgorithm.SSHA512},
                {null, CipherAlgorithm.BCRYPT},
                {emptyString, CipherAlgorithm.BCRYPT},
                {stringSmallerThanBlock, CipherAlgorithm.BCRYPT},
                {stringBiggerThanBlock, CipherAlgorithm.BCRYPT},
                {null, null},
                {emptyString, null},
                {stringSmallerThanBlock, null},
                {stringBiggerThanBlock, null}
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
    public void testEncode() {
        try {
            String encoded = encryptor.encode(stringToEncode, cipherAlgorithm);
            System.out.println(cipherAlgorithm + ":\t" + encoded);
            if (stringToEncode == null) {
                Assert.assertNull(encoded);
            } else {
                boolean success = encryptor.verify(stringToEncode, cipherAlgorithm, encoded);
                // assuming verify() method is correct
                Assert.assertTrue(success);
            }
        } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            // test fails if an exception occurs
            fail("Exception occurred, test failed");
        }
    }

}
