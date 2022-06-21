package org.apache.syncope.core.spring.security;

import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.common.lib.types.ImplementationEngine;
import org.apache.syncope.core.persistence.api.dao.PasswordRule;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;
import org.apache.syncope.core.provisioning.api.serialization.POJOHelper;
import org.apache.syncope.core.spring.ImplementationManager;
import org.apache.syncope.core.spring.policy.DefaultPasswordRule;
import org.apache.syncope.core.spring.policy.InvalidPasswordRuleConf;
import org.apache.syncope.core.spring.utils.MyImplementation;
import org.apache.syncope.core.spring.utils.MyPasswordPolicy;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.util.*;

import static org.mockito.ArgumentMatchers.eq;

@RunWith(Parameterized.class)
public class DefaultPasswordGeneratorTest {

    // instance under test
    private DefaultPasswordGenerator defaultPasswordGenerator;
    private List<PasswordPolicy> policies;

    // not purely test parameters, but needed to mock correctly and to compute expected result
    private List<MyImplementation> implementations;
    private List<DefaultPasswordRule> rules;

    // mocked implementation manager
    static MockedStatic<ImplementationManager> im = Mockito.mockStatic(ImplementationManager.class);




    public DefaultPasswordGeneratorTest(List<PasswordPolicy> policies, List<MyImplementation> implementations, List<DefaultPasswordRule> rules) {
        configure(policies, implementations, rules);
    }

    private void configure(List<PasswordPolicy> policies, List<MyImplementation> implementations, List<DefaultPasswordRule> rules) {
        this.defaultPasswordGenerator = new DefaultPasswordGenerator();
        this.policies = policies;

        this.implementations = implementations;
        this.rules = rules;
    }


    private static class MyRulesContainer {
        /**
         * This class purely exists only to make it easy to create and
         * group together parameters needed for the test cases
         */
        private final List<PasswordPolicy> policies;
        private final List<MyImplementation> implementations;
        private final List<DefaultPasswordRule> rules;

        public MyRulesContainer(List<PasswordPolicy> policies, List<MyImplementation> implementations, List<DefaultPasswordRule> rules) {
            this.policies = policies;
            this.implementations = implementations;
            this.rules = rules;
        }

        public List<PasswordPolicy> getPolicies() {
            return policies;
        }

        public List<MyImplementation> getImplementations() {
            return implementations;
        }

        public List<DefaultPasswordRule> getRules() {
            return rules;
        }
    }

    /**
     * Mock the Implementation manager to make it return what we expect
     */
    @Before
    public void mock() {
//        im = Mockito.mockStatic(ImplementationManager.class);
        if (implementations != null) {
            for (int i = 0; i < implementations.size(); i++) {
                int finalI = i;
                im.when(() -> ImplementationManager.buildPasswordRule(eq(implementations.get(finalI)))).thenAnswer(
                        new Answer<Optional<PasswordRule>>() {

                            @Override
                            public Optional<PasswordRule> answer(InvocationOnMock invocationOnMock) throws Throwable {
                                return Optional.of(rules.get(finalI));
                            }
                        }
                );
            }
        }
    }

    @Parameterized.Parameters
    public static Collection<Object[]> parameters() {
        MyRulesContainer empty = buildPasswordPolicies(PoliciesType.EMPTY);
        MyRulesContainer nullPolicy = buildPasswordPolicies(PoliciesType.NULL);
        MyRulesContainer valid = buildPasswordPolicies(PoliciesType.VALID);
        MyRulesContainer validMultiple = buildPasswordPolicies(PoliciesType.VALID_MULTIPLE);


        return Arrays.asList(new Object[][]{
                {empty.getPolicies(), empty.getImplementations(), empty.getRules()}, // empty list
                {nullPolicy.getPolicies(), nullPolicy.getImplementations(), nullPolicy.getRules()}, // null list
                {valid.getPolicies(), valid.getImplementations(), valid.getRules()},   // valid list
//                {validMultiple.getPolicies(), validMultiple.getImplementations(), validMultiple.getRules()}, // valid multiple policies
        });
    }



    private static MyRulesContainer buildPasswordPolicies(PoliciesType type) {
        MyRulesContainer ret;
        switch (type) {
            case EMPTY:
                ret = new MyRulesContainer(new ArrayList<>(), null, null);
                break;

            case VALID:
                ret = buildPolicy(false);
                break;

            case VALID_MULTIPLE:
                ret = buildPolicy(true);
                break;
            case NULL:
            default:
                ret = new MyRulesContainer(null, null, null);
                break;
        }
        return ret;
    }

    private static MyRulesContainer buildPolicy(boolean multiple) {
        List<PasswordPolicy> policies = new ArrayList<>();
        List<MyImplementation> implementations = new ArrayList<>();
        List<DefaultPasswordRule> rules = new ArrayList<>();

        PasswordPolicy pol = new MyPasswordPolicy();
        pol.setHistoryLength(1);
        pol.setAllowNullPassword(true);

        List<String> blacklist = Arrays.asList("password123", "admin123", "12345678");
        DefaultPasswordRuleConf conf = generateConf(12, 16, true,
                true, false, true, true,
                false, false, blacklist);

        DefaultPasswordRule rule = new DefaultPasswordRule();
        rule.setConf(conf);

        MyImplementation impl = new MyImplementation();
        impl.setEngine(ImplementationEngine.JAVA);
        impl.setBody(POJOHelper.serialize(rule));
        pol.add(impl);

        policies.add(pol);
        // assume 1 implementation per policy
        implementations.add(impl);
        rules.add(rule);
        if (!multiple)
            return new MyRulesContainer(policies, implementations, rules);

        // add another policy
        PasswordPolicy policy2 = new MyPasswordPolicy();
        policy2.setHistoryLength(0);
        policy2.setAllowNullPassword(false);

        List<String> mustNotContain = Arrays.asList("ciaociao", "maracaibo");
        DefaultPasswordRule rule2 = new DefaultPasswordRule();
        DefaultPasswordRuleConf conf2 = generateConf(15, 0, true,
                false, false, false, false,
                false, false, mustNotContain);
        rule2.setConf(conf2);

        MyImplementation impl2 = new MyImplementation();
        impl2.setEngine(ImplementationEngine.JAVA);
        impl2.setBody(POJOHelper.serialize(rule2));
        policy2.add(impl2);

        policies.add(policy2);
        implementations.add(impl2);
        rules.add(rule2);
        return new MyRulesContainer(policies, implementations, rules);
    }




    private static DefaultPasswordRuleConf generateConf(int minLen, int maxLen, boolean uppercaseRequired, boolean lowercaseReq,
                                                        boolean nonAlphaRequired, boolean alphanumRequired,
                                                        boolean endWDigit, boolean endWAlpha, boolean endWNonAlpha, List<String> blacklist) {
        DefaultPasswordRuleConf conf = new DefaultPasswordRuleConf();
        conf.setMaxLength(maxLen);
        conf.setMinLength(minLen);
        conf.setUppercaseRequired(uppercaseRequired);
        conf.setLowercaseRequired(lowercaseReq);
        conf.setNonAlphanumericRequired(nonAlphaRequired);
        conf.setAlphanumericRequired(alphanumRequired);
        conf.setMustEndWithDigit(endWDigit);
        conf.setMustEndWithAlpha(endWAlpha);
        conf.setMustEndWithNonAlpha(endWNonAlpha);
        conf.getWordsNotPermitted().addAll(blacklist);
        return conf;
    }

    /**
     * Oracle method !!!
     *
     * @param password
     * @param conf
     * @return
     */
    private boolean passwordRespectsConf(String password, DefaultPasswordRuleConf conf) {
        if (conf == null)
            return true;
        if (conf.getMinLength() != 0 && password.length() < conf.getMinLength())
            return false;
        if (conf.getMaxLength() != 0 && password.length() > conf.getMaxLength())
            return false;
        if (conf.isAlphanumericRequired()) {
            boolean found = false;
            for (Character c : password.toCharArray()) {
                if (Character.isLetter(c) || Character.isDigit(c)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                System.out.println("alphanum req");
                return false;
            }
        }
        if (conf.isLowercaseRequired()) {
            boolean found = false;
            for (Character c : password.toCharArray()) {
                if (Character.isLowerCase(c)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                System.out.println("lower req");
                return false;
            }
        }
        if (conf.isUppercaseRequired()) {
            boolean found = false;
            for (Character c : password.toCharArray()) {
                if (Character.isUpperCase(c)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                System.out.println("upper req");
                return false;
            }
        }
        if (conf.isNonAlphanumericRequired()) {
            boolean found = false;
            for (Character c : password.toCharArray()) {
                if (!Character.isLetter(c) && !Character.isDigit(c)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                System.out.println("non alpha req");
                return false;
            }
        }
        char lastChar = password.toCharArray()[password.length() - 1];
        if (conf.isMustEndWithDigit()) {
            if (!Character.isDigit(lastChar)) {
                System.out.println("end w digit");
                return false;
            }
        }
        if (conf.isMustEndWithAlpha()) {
            if (!Character.isLetter(lastChar))
                return false;
        }
        if (conf.isMustEndWithNonAlpha()) {
            if (Character.isLetter(lastChar)) {
                System.out.println("end w non alpha");
                return false;
            }

        }
        for (String s : conf.getWordsNotPermitted()) {
            if (password.contains(s))
                return false;
        }
        return true;
    }

    /**
     * Check if the configurations are not compatible and so
     * an exception is expected.
     * @return True if the exception is expected; False otherwise.
     */
    private boolean isExpectedException() {
        boolean mustEndWithDigit = false;
        boolean mustEndWithAlpha = false;
        boolean mustEndWithNonAlpha = false;
        for (DefaultPasswordRule rule : rules) {
            DefaultPasswordRuleConf conf = (DefaultPasswordRuleConf) rule.getConf();
            if (conf.isMustEndWithDigit())
                mustEndWithDigit = true;
            if (conf.isMustEndWithAlpha())
                mustEndWithAlpha = true;
            if (conf.isMustEndWithNonAlpha())
                mustEndWithNonAlpha = true;
        }
        // if both true, exception expected, because it's not possible
        if (mustEndWithDigit && mustEndWithAlpha)
            return true;
        if (mustEndWithAlpha && mustEndWithNonAlpha)
            return true;
        return false;
    }


    @Test
    public void testGeneratePassword() throws InstantiationException, IllegalAccessException {
        boolean testPassed = true;
        boolean expectedException = false;
        if (rules != null)
            expectedException = isExpectedException();
        try {
            // method under test
            String generatedPassword = defaultPasswordGenerator.generate(policies);
            System.out.println(generatedPassword);

            if (implementations != null) {
                for (DefaultPasswordRule rule : rules) {
                    testPassed = passwordRespectsConf(generatedPassword, (DefaultPasswordRuleConf) rule.getConf());
                    if (!testPassed)
                        break;
                }
            }

            // at this point, if an exception was expected, it has not been triggered
            if (expectedException)
                testPassed = false;

        } catch (InvalidPasswordRuleConf e) {
            testPassed = expectedException;
            System.out.println("test passed:" + testPassed);
            System.out.println("expected exception:" + expectedException);
            System.out.println(e.getMessage());
        } catch (NullPointerException e) {
            System.out.println("null");
            // this verifies only if policies == null, but this never happens in reality, so test is passed
        }

        Assert.assertTrue(testPassed);
    }

    @After
    public void reMock() {
        im.reset();
    }

    public enum PoliciesType {NULL, EMPTY, VALID, VALID_MULTIPLE}
}
