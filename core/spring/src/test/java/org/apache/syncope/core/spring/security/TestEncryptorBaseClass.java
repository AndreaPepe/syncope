package org.apache.syncope.core.spring.security;

import org.apache.syncope.core.spring.ApplicationContextProvider;
import org.apache.syncope.core.spring.utils.MyConfigurableApplicationContext;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;

public abstract class TestEncryptorBaseClass {
    public static MockedStatic<ApplicationContextProvider> appCtxProviderMocked;

    @BeforeClass
    public static void doMocks() {
        DefaultListableBeanFactory customFactory = new DefaultListableBeanFactory();

        // MyConfigurableApplicationContext return a bean based on this string on the method getBean() !
        customFactory.registerSingleton("securityProperties", new SecurityProperties());

        appCtxProviderMocked = Mockito.mockStatic(ApplicationContextProvider.class);
        appCtxProviderMocked.when(ApplicationContextProvider::getBeanFactory).thenReturn(customFactory);
        appCtxProviderMocked.when(ApplicationContextProvider::getApplicationContext).thenReturn(new MyConfigurableApplicationContext(customFactory));
    }

    @AfterClass
    public static void closeCtxProvider() {
        if (appCtxProviderMocked != null)
            appCtxProviderMocked.close();
    }
}
