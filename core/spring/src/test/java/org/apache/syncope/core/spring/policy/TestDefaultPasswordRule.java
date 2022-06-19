package org.apache.syncope.core.spring.policy;

import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.spring.policy.DefaultPasswordRule;
import org.apache.syncope.core.spring.policy.PasswordPolicyException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.apache.syncope.core.spring.utils.UserImplementation;

import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class TestDefaultPasswordRule {

    private DefaultPasswordRule ruleUnderTest;
    private DefaultPasswordRuleConf configuration;
    private User user;


    public TestDefaultPasswordRule(DefaultPasswordRuleConf conf, String username, String password, CipherAlgorithm algo){
        configure(conf,username,password,algo);
    }

    private void configure(DefaultPasswordRuleConf conf,  String username, String password, CipherAlgorithm algo){
        this.ruleUnderTest = new DefaultPasswordRule();
        this.configuration = conf;
        // instance under test
        ruleUnderTest.setConf(conf);

        // personal implementation of interface
        this.user = new UserImplementation(username, password, algo);
    }

    @Parameterized.Parameters
    public static Collection<Object[]> parameters(){
        return Arrays.asList(new Object[][]{
           // parameters of the test
                {setUpRulesConf(-1,20,false,false), "user", "pwd", CipherAlgorithm.AES},
                {setUpRulesConf(1,2,true, true), "admin", "bc2", CipherAlgorithm.BCRYPT}
        });
    }

    private static DefaultPasswordRuleConf setUpRulesConf(int minLen, int maxLen, boolean digitRequired, boolean alphanumericRequired){
        DefaultPasswordRuleConf conf = new DefaultPasswordRuleConf();
        conf.setMinLength(minLen);
        conf.setMaxLength(maxLen);
        conf.setDigitRequired(digitRequired);
        conf.setAlphanumericRequired(alphanumericRequired);
        return conf;
    }

    // Oracle method
    private boolean isValidPassword(DefaultPasswordRuleConf config, String password){

        int minLen = config.getMinLength();
        int maxLen = config.getMaxLength();
        boolean digitRequired = config.isDigitRequired();
        boolean alphanumericRequired = config.isAlphanumericRequired();

        if (password.length() < minLen){
            return false;
        }
        if ( password.length() > maxLen){
            return false;
        }
        if (digitRequired){
            boolean containsDigit = false;
            for (Character c : password.toCharArray()){
                if (Character.isDigit(c)){
                    containsDigit = true;
                    break;
                }
            }
            if (!containsDigit)
                return false;
        }
        if (alphanumericRequired){
            boolean containsAlphaNumeric = false;
            for (Character c : password.toCharArray()){
                if(Character.isAlphabetic(c) || Character.isDigit(c)){
                    containsAlphaNumeric = true;
                    break;
                }
            }
            if(!containsAlphaNumeric)
                return false;
        }
        return true;
    }

    @Test
    public void testEnforce(){
        boolean expectedResult = isValidPassword(this.configuration, this.user.getClearPassword());
        boolean authenticated = true;
        try{
            ruleUnderTest.enforce(this.user);
        }catch (PasswordPolicyException e){
            // rules not respected
            authenticated = false;
        }
        Assert.assertEquals(expectedResult, authenticated);
    }

}
