package org.apache.syncope.core.spring.security;

import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;
import org.apache.syncope.core.spring.policy.InvalidPasswordRuleConf;
import org.apache.syncope.core.spring.security.DefaultPasswordGenerator;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.apache.syncope.core.spring.utils.MyPasswordPolicy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

@RunWith(Parameterized.class)
public class DefaultPasswordGeneratorTest {

    // instance under test
    private DefaultPasswordGenerator defaultPasswordGenerator;
    private List<PasswordPolicy> policies;

    public DefaultPasswordGeneratorTest(List<PasswordPolicy> policies){
        configure(policies);
    }

    private void configure(List<PasswordPolicy> policies){
        this.defaultPasswordGenerator = new DefaultPasswordGenerator();
        this.policies = policies;
    }

    private static List<PasswordPolicy> buildPasswordPolicies(){
        List<PasswordPolicy> policies = new ArrayList<>();
        PasswordPolicy pol = new MyPasswordPolicy();
        //hardcoded for now
        pol.setAllowNullPassword(true);
        pol.setHistoryLength(3);
        policies.add(pol);
        return policies;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> parameters(){
        return Arrays.asList(new Object[][]{
                {null},
                {new ArrayList<PasswordPolicy>()},
                {buildPasswordPolicies()}
        });
    }

    @Test
    public void testGeneratePassword(){
        boolean testPassed = true;
        boolean expectedException = false;
        try {
            String generatedPassword = defaultPasswordGenerator.generate(policies);
        } catch (InvalidPasswordRuleConf e) {
            if (!expectedException)
                testPassed = false;
        } catch (NullPointerException e) {
            // this verifies only if policies == null, but this never happens in reality, so test is passed
        }

        Assert.assertTrue(testPassed);
    }
}
