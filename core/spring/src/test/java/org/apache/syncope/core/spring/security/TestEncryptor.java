package org.apache.syncope.core.spring.security;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.ApplicationContextProvider;
import org.apache.syncope.core.spring.utils.MyConfigurableApplicationContext;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;

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
public class TestEncryptor {
    private Encryptor encryptor;
    private String stringToEncode;
    private CipherAlgorithm cipherAlgorithm;

    public static MockedStatic<ApplicationContextProvider> appCtxProviderMocked;

    public TestEncryptor(String toBeEncoded, CipherAlgorithm cipherAlgorithm){
        configure(toBeEncoded, cipherAlgorithm);
    }

    private void configure(String stringToEncode, CipherAlgorithm cipherAlgorithm){
        // instance under test
        if (encryptor == null)
            encryptor = Encryptor.getInstance();
        this.stringToEncode = stringToEncode;
        this.cipherAlgorithm = cipherAlgorithm;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> parameters(){
        return Arrays.asList(new Object[][]{
                // for now only unidimensional
                {"encodeMe", CipherAlgorithm.AES},
                {"", CipherAlgorithm.BCRYPT},
                {null, CipherAlgorithm.SHA},
                {"aaa", CipherAlgorithm.SHA256},
                {"aaa", CipherAlgorithm.SHA512},
                {"aaa", CipherAlgorithm.SHA1},
                {"aaa", CipherAlgorithm.SSHA},
                {"aaa", CipherAlgorithm.SMD5},
                {"aaa", CipherAlgorithm.SSHA1},
                {"aaa", CipherAlgorithm.SSHA256},
                {"aaa", CipherAlgorithm.SSHA512},
                {"aaa", null}
        });
    }


    @BeforeClass
    public static void doMocks(){
        DefaultListableBeanFactory customFactory = new DefaultListableBeanFactory();

        // MyConfigurableApplicationContext return a bean based on this string on the method getBean() !
        customFactory.registerSingleton("securityProperties", new SecurityProperties());

        appCtxProviderMocked = Mockito.mockStatic(ApplicationContextProvider.class);
        appCtxProviderMocked.when(ApplicationContextProvider::getBeanFactory).thenReturn(customFactory);
        appCtxProviderMocked.when(ApplicationContextProvider::getApplicationContext).thenReturn(new MyConfigurableApplicationContext(customFactory));
    }

    @Test
    public void testEncode(){
        try{
            String encoded = encryptor.encode(stringToEncode, cipherAlgorithm);
            if (stringToEncode == null){
                Assert.assertNull(encoded);
            }else {
                boolean success = encryptor.verify(stringToEncode, cipherAlgorithm, encoded);
                Assert.assertTrue(success);
            }
        }catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            fail("Exception occurred, test failed");
        }
    }


    @AfterClass
    public static void closeCtxProvider(){
        if (appCtxProviderMocked != null)
            appCtxProviderMocked.close();
    }
}
