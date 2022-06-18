import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.ApplicationContextProvider;
import org.apache.syncope.core.spring.security.Encryptor;
import org.apache.syncope.core.spring.security.SecurityProperties;
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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class EncryptorTest {

    private static Encryptor encryptor;
    private String toBeEncoded;
    private CipherAlgorithm cipherAlgorithm;
    static MockedStatic<ApplicationContextProvider> appCtxProviderMocked;


    public EncryptorTest(String toBeEncoded, CipherAlgorithm cipherAlgorithm){
        configure(toBeEncoded, cipherAlgorithm);
    }

    private void configure(String toBeEncoded, CipherAlgorithm cipherAlgorithm){
        //encryptor = Encryptor.getInstance();
        this.toBeEncoded = toBeEncoded;
        this.cipherAlgorithm = cipherAlgorithm;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> parameters(){
        return Arrays.asList(new Object[][]{
                {"This text has to be encoded", CipherAlgorithm.AES},
                {"", CipherAlgorithm.BCRYPT},
                {null, CipherAlgorithm.SMD5},
                {null, null}
        });
    }

    @BeforeClass
    public static void setup(){
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton("securityProperties", new SecurityProperties());

        appCtxProviderMocked = Mockito.mockStatic(ApplicationContextProvider.class);
        appCtxProviderMocked.when(ApplicationContextProvider::getBeanFactory).thenReturn(beanFactory);
        appCtxProviderMocked.when(ApplicationContextProvider::getApplicationContext).thenReturn(new DummyConfigurableApplicationContext());
        encryptor = Encryptor.getInstance();
    }

    @Test
    public void testEncoding(){
        try {
            String encoded = encryptor.encode(toBeEncoded, cipherAlgorithm);
            if (toBeEncoded == null){
                Assert.assertNull(encoded);
            }else {
                boolean isWellEncoded = encryptor.verify(toBeEncoded, cipherAlgorithm, encoded);
                assertTrue(isWellEncoded);
            }
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            fail("Unexpected exception occurred");
        }
    }


    @AfterClass
    public static void tearDown(){
        if (appCtxProviderMocked != null)
            appCtxProviderMocked.close();
    }
}
