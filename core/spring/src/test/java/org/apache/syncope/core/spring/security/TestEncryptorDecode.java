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

@RunWith(Parameterized.class)
public class TestEncryptorDecode extends TestEncryptorBaseClass {
    private static final String SECRET_KEY = "secret!";
    private Encryptor encryptor;
    private String encoded;
    private CipherAlgorithm cipherAlgorithm;

    public TestEncryptorDecode(TestString testString, CipherAlgorithm cipherAlgorithm) {
        configure(testString, cipherAlgorithm);
    }

    private void configure(TestString testString, CipherAlgorithm cipherAlgorithm) {
        // instance under test
        if (encryptor == null)
            encryptor = Encryptor.getInstance(SECRET_KEY);
        switch (testString) {

            case NULL:
                this.encoded = TestString.NULL.getString();
                break;
            case EMPTY:
                this.encoded = TestString.EMPTY.getString();
                break;
            case ENCODE:
                try {
                    // always encode with AES
                    this.encoded = encryptor.encode(TestString.ENCODE.getString(), CipherAlgorithm.AES);
                } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException |
                        InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }
                break;
            case CRAP:
                this.encoded = TestString.CRAP.getString();
                break;
        }
        this.cipherAlgorithm = cipherAlgorithm;

    }

    @Parameterized.Parameters
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                {TestString.NULL, null},
                {TestString.EMPTY, null},
                {TestString.ENCODE, null},
                {TestString.CRAP, null},
                {TestString.NULL, CipherAlgorithm.AES},
                {TestString.EMPTY, CipherAlgorithm.AES},
                {TestString.ENCODE, CipherAlgorithm.AES},
                {TestString.CRAP, CipherAlgorithm.AES},
                {TestString.NULL, CipherAlgorithm.BCRYPT},
                {TestString.EMPTY, CipherAlgorithm.BCRYPT},
                {TestString.ENCODE, CipherAlgorithm.BCRYPT},
                {TestString.CRAP, CipherAlgorithm.BCRYPT},
        });
    }

    @Test
    public void testDecode() {
        boolean expectedNull = false;
        boolean expectedException = false;
        if (encoded == null)
            expectedNull = true;
        else if (cipherAlgorithm != CipherAlgorithm.AES)
            expectedNull = true;
        else if (encoded.equals(TestString.CRAP.getString()))
            expectedException = true;

        try {
            String decoded = encryptor.decode(encoded, cipherAlgorithm);
            System.out.println(encoded + "\t" + decoded);
            if (decoded == null)
                Assert.assertTrue(expectedNull);
            else if (encoded.equals(TestString.EMPTY.getString()))
                Assert.assertEquals(TestString.EMPTY.getString(), decoded);
            else
                Assert.assertTrue(encryptor.verify(decoded, CipherAlgorithm.AES, encoded));
        } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            System.out.println(e.getClass());
            if (expectedException)
                Assert.assertTrue(true);
        }
    }


    public enum TestString {
        NULL(null),
        EMPTY(""),
        ENCODE("myString"),
        CRAP("randomCrap");

        private final String string;

        TestString(String s) {
            string = s;
        }

        public String getString() {
            return string;
        }
    }
}
