package org.apache.syncope.core.spring.security;

import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.common.lib.types.ImplementationEngine;
import org.apache.syncope.core.persistence.api.dao.PasswordRule;
import org.apache.syncope.core.persistence.api.entity.Implementation;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;
import org.apache.syncope.core.persistence.api.entity.resource.ExternalResource;
import org.apache.syncope.core.provisioning.api.serialization.POJOHelper;
import org.apache.syncope.core.spring.ImplementationManager;
import org.apache.syncope.core.spring.policy.DefaultPasswordRule;
import org.apache.syncope.core.spring.policy.InvalidPasswordRuleConf;
import org.apache.syncope.core.spring.utils.MyExternalResource;
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
    private ExternalResource externalResource;

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

        // configure ExternalResource
        if (policies == null || policies.isEmpty()) {
            this.externalResource = new MyExternalResource(null);
        } else {
            // get the first policy; in effect, we always have one, but we could have more
            this.externalResource = new MyExternalResource(policies.get(0));
        }
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
        MyRulesContainer empty = buildPolicy(PoliciesType.EMPTY);
        MyRulesContainer nullPolicy = buildPolicy(PoliciesType.NULL);
        MyRulesContainer valid = buildPolicy(PoliciesType.VALID);
        MyRulesContainer sizeBothNeg = buildPolicy(PoliciesType.SIZE_BOTH_NEG);
        MyRulesContainer onlyMaxLenNeg = buildPolicy(PoliciesType.ONLY_MAX_LEN_NEG);
        MyRulesContainer bothZero = buildPolicy(PoliciesType.BOTH_SIZE_ZERO);
        MyRulesContainer onlyMaxSizeZero = buildPolicy(PoliciesType.ONLY_MAX_SIZE_ZERO);
        MyRulesContainer bothTen = buildPolicy(PoliciesType.SIZE_BOTH_TEN);
        MyRulesContainer startAndNotWithDigit = buildPolicy(PoliciesType.START_AND_NOT_WITH_DIGIT);
        MyRulesContainer startAndNotWithNonAlpha = buildPolicy(PoliciesType.START_AND_NOT_WITH_NON_ALPHA);
        MyRulesContainer startAndNotWithAlpha = buildPolicy(PoliciesType.START_AND_NOT_WITH_ALPHA);
        MyRulesContainer endAndNotWithDigit = buildPolicy(PoliciesType.END_AND_NOT_WITH_DIGIT);
        MyRulesContainer endAndNotWithNonAlpha = buildPolicy(PoliciesType.END_AND_NOT_WITH_NON_ALPHA);
        MyRulesContainer endAndNotWithAlpha = buildPolicy(PoliciesType.END_AND_NOT_WITH_ALPHA);
        MyRulesContainer startWithDigitAndNonAlpha = buildPolicy(PoliciesType.START_WITH_DIGIT_AND_NON_ALPHA);
        MyRulesContainer startWithDigitAndAlpha = buildPolicy(PoliciesType.START_WITH_DIGIT_AND_ALPHA);
        MyRulesContainer startWithAlphaAndNonAlpha = buildPolicy(PoliciesType.START_WITH_ALPHA_AND_NON_ALPHA);
        MyRulesContainer startWithAll = buildPolicy(PoliciesType.START_WITH_ALL);
        MyRulesContainer endWithDigitAndNonAlpha = buildPolicy(PoliciesType.END_WITH_DIGIT_AND_NON_ALPHA);
        MyRulesContainer endWithDigitAndAlpha = buildPolicy(PoliciesType.END_WITH_DIGIT_AND_ALPHA);
        MyRulesContainer endWithAlphaAndNonAlpha = buildPolicy(PoliciesType.END_WITH_ALPHA_AND_NON_ALPHA);
        MyRulesContainer endWithAll = buildPolicy(PoliciesType.END_WITH_ALL);
        MyRulesContainer notStartWithAll = buildPolicy(PoliciesType.NOT_START_WITH_ALL);
        MyRulesContainer notEndWithAll = buildPolicy(PoliciesType.NOT_END_WITH_ALL);


        return Arrays.asList(new Object[][]{
                // first iteration's tests
                {empty.getPolicies(), empty.getImplementations(), empty.getRules()},
                {nullPolicy.getPolicies(), nullPolicy.getImplementations(), nullPolicy.getRules()},
                {valid.getPolicies(), valid.getImplementations(), valid.getRules()},

                // test cases on password size
                {sizeBothNeg.getPolicies(), sizeBothNeg.getImplementations(), sizeBothNeg.getRules()},
                {onlyMaxLenNeg.getPolicies(), onlyMaxLenNeg.getImplementations(), onlyMaxLenNeg.getRules()},
                {bothZero.getPolicies(), bothZero.getImplementations(), bothZero.getRules()},
                // BUG
//                {onlyMaxSizeZero.getPolicies(), onlyMaxSizeZero.getImplementations(), onlyMaxSizeZero.getRules()},
                {bothTen.getPolicies(), bothTen.getImplementations(), bothTen.getRules()},

                // test cases on rules "must or must not Start/End with"
                {startAndNotWithDigit.getPolicies(), startAndNotWithDigit.getImplementations(), startAndNotWithDigit.getRules()},
                {startAndNotWithNonAlpha.getPolicies(), startAndNotWithNonAlpha.getImplementations(), startAndNotWithNonAlpha.getRules()},
                {startAndNotWithAlpha.getPolicies(), startAndNotWithAlpha.getImplementations(), startAndNotWithAlpha.getRules()},
                //BUG
//                {endAndNotWithDigit.getPolicies(), endAndNotWithDigit.getImplementations(), endAndNotWithDigit.getRules()},
                {endAndNotWithNonAlpha.getPolicies(), endAndNotWithNonAlpha.getImplementations(), endAndNotWithNonAlpha.getRules()},
                {endAndNotWithAlpha.getPolicies(), endAndNotWithAlpha.getImplementations(), endAndNotWithAlpha.getRules()},
                {startWithDigitAndNonAlpha.getPolicies(), startWithDigitAndNonAlpha.getImplementations(), startWithDigitAndNonAlpha.getRules()},
                {startWithDigitAndAlpha.getPolicies(), startWithDigitAndAlpha.getImplementations(), startWithDigitAndAlpha.getRules()},
                //BUG
//                {startWithAlphaAndNonAlpha.getPolicies(), startWithAlphaAndNonAlpha.getImplementations(), startWithAlphaAndNonAlpha.getRules()},
                {startWithAll.getPolicies(), startWithAll.getImplementations(), startWithAll.getRules()},
                {endWithDigitAndNonAlpha.getPolicies(), endWithDigitAndNonAlpha.getImplementations(), endWithDigitAndNonAlpha.getRules()},
                {endWithDigitAndAlpha.getPolicies(), endWithDigitAndAlpha.getImplementations(), endWithDigitAndAlpha.getRules()},
                // BUG
//                {endWithAlphaAndNonAlpha.getPolicies(), endWithAlphaAndNonAlpha.getImplementations(), endWithAlphaAndNonAlpha.getRules()},
                {endWithAll.getPolicies(), endWithAll.getImplementations(), endWithAll.getRules()},
                // BUG
//                {notStartWithAll.getPolicies(), notStartWithAll.getImplementations(), notStartWithAll.getRules()},
                // BUG
//                {notEndWithAll.getPolicies(), notEndWithAll.getImplementations(), notEndWithAll.getRules()}
        });
    }


    /**
     * This method build the policies accordingly to the designed test cases
     *
     * @param type type of test case
     * @return rules container
     */
    private static MyRulesContainer buildPolicy(PoliciesType type) {
        List<PasswordPolicy> policies = new ArrayList<>();
        List<MyImplementation> implementations = new ArrayList<>();
        List<DefaultPasswordRule> rules = new ArrayList<>();
        PasswordPolicy pol = new MyPasswordPolicy();
        // equals for all cases except SIZE_BOTH_NEG; it can overwrite them
        pol.setHistoryLength(1);
        pol.setAllowNullPassword(false);

        DefaultPasswordRuleConf conf;

        switch (type) {
            case EMPTY:
                return new MyRulesContainer(new ArrayList<>(), null, null);

            case VALID:
                conf = generateConf(10, 10, true, true, true, true, true,
                        false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case SIZE_BOTH_NEG:
                pol.setHistoryLength(0);
                pol.setAllowNullPassword(true);
                List<String> notAllowedWords = new ArrayList<>();
                notAllowedWords.add("password123");
                conf = generateConf(-1, -1, false, false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        true, notAllowedWords, Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case ONLY_MAX_LEN_NEG:
                List<String> notAllowedSchemas = new ArrayList<>();
                notAllowedSchemas.add("schema");
                conf = generateConf(0, -1, false, false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, Collections.emptyList(), notAllowedSchemas, Collections.emptyList(), Collections.emptyList());
                break;
            case BOTH_SIZE_ZERO:
                List<String> notAllowedPrefixes = new ArrayList<>();
                notAllowedPrefixes.add("prefix");
                conf = generateConf(0, 0, true, true, true, true, true,
                        false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), notAllowedPrefixes, Collections.emptyList());
                break;
            case ONLY_MAX_SIZE_ZERO:
                List<String> notAllowedSuffixes = new ArrayList<>();
                notAllowedSuffixes.add("suffix");
                conf = generateConf(1, 0, false, false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), notAllowedSuffixes);
                break;
            case SIZE_BOTH_TEN:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case MIN_SIZE_BIGGER_TEN:
                conf = generateConf(11, 10, false, false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case START_AND_NOT_WITH_DIGIT:
                conf = generateConf(10, 10, false, false, false, false, false,
                        true, true, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case END_AND_NOT_WITH_DIGIT:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, false, true, true,
                        false, false, false, false,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case START_AND_NOT_WITH_NON_ALPHA:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, false, false, false,
                        true, true, false, false,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case START_AND_NOT_WITH_ALPHA:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, false, false, false,
                        false, false, true, true,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case END_AND_NOT_WITH_NON_ALPHA:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        true, true, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case END_AND_NOT_WITH_ALPHA:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        false, false, true, true,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case START_WITH_DIGIT_AND_NON_ALPHA:
                conf = generateConf(10, 10, false, false, false, false, false,
                        true, false, false, false,
                        true, false, false, false,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case START_WITH_DIGIT_AND_ALPHA:
                conf = generateConf(10, 10, false, false, false, false, false,
                        true, false, false, false,
                        false, false, true, false,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case START_WITH_ALPHA_AND_NON_ALPHA:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, false, false, false,
                        true, false, true, false,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case START_WITH_ALL:
                conf = generateConf(10, 10, false, false, false, false, false,
                        true, false, false, false,
                        true, false, true, false,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case END_WITH_DIGIT_AND_NON_ALPHA:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, false, true, false,
                        false, false, false, false,
                        true, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case END_WITH_DIGIT_AND_ALPHA:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, false, true, false,
                        false, false, false, false,
                        false, false, true, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case END_WITH_ALPHA_AND_NON_ALPHA:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, false, false, false,
                        false, false, false, false,
                        true, false, true, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case END_WITH_ALL:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, false, true, false,
                        false, false, false, false,
                        true, false, true, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case NOT_START_WITH_ALL:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, true, false, false,
                        false, true, false, true,
                        false, false, false, false,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;
            case NOT_END_WITH_ALL:
                conf = generateConf(10, 10, false, false, false, false, false,
                        false, false, false, true,
                        false, false, false, false,
                        false, true, false, true,
                        false, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
                break;

            case NULL:
            default:
                return new MyRulesContainer(null, null, null);
        }

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
        return new MyRulesContainer(policies, implementations, rules);
    }


    private static DefaultPasswordRuleConf generateConf(int minLen, int maxLen,
                                                        boolean nonAlphaReq, boolean alphaReq, boolean digitReq, boolean lowcaseReq, boolean upcaseReq,
                                                        boolean startWDigit, boolean notStartWDigit, boolean endWDigit, boolean notEndWDigit,
                                                        boolean startWNonAlpha, boolean notStartWNonAlpha, boolean startWAlpha, boolean notStartWAlpha,
                                                        boolean endWNonAlpha, boolean notEndWNonAlpha, boolean endWAlpha, boolean notEndWAlpha,
                                                        boolean usernameAllowed,
                                                        List<String> notPermitted, List<String> schemas, List<String> prefixes, List<String> suffixes) {
        DefaultPasswordRuleConf conf = new DefaultPasswordRuleConf();
        // sizes
        conf.setMinLength(minLen);
        conf.setMaxLength(maxLen);

        // character required
        conf.setNonAlphanumericRequired(nonAlphaReq);
        conf.setAlphanumericRequired(alphaReq);
        conf.setDigitRequired(digitReq);
        conf.setLowercaseRequired(lowcaseReq);
        conf.setUppercaseRequired(upcaseReq);

        // start or end w/wo digit
        conf.setMustStartWithDigit(startWDigit);
        conf.setMustntStartWithDigit(notStartWDigit);
        conf.setMustEndWithDigit(endWDigit);
        conf.setMustntEndWithDigit(notEndWDigit);

        // start w/wo alpha and non alpha
        conf.setMustStartWithNonAlpha(startWNonAlpha);
        conf.setMustntStartWithNonAlpha(notStartWNonAlpha);
        conf.setMustStartWithAlpha(startWAlpha);
        conf.setMustntStartWithAlpha(notStartWAlpha);

        // end w/wo alpha and non alpha
        conf.setMustEndWithNonAlpha(endWNonAlpha);
        conf.setMustntEndWithNonAlpha(notEndWNonAlpha);
        conf.setMustEndWithAlpha(endWAlpha);
        conf.setMustntEndWithAlpha(notEndWAlpha);

        // username allowed and blacklists
        conf.setUsernameAllowed(usernameAllowed);
        conf.getWordsNotPermitted().addAll(notPermitted);
        conf.getSchemasNotPermitted().addAll(schemas);
        conf.getPrefixesNotPermitted().addAll(prefixes);
        conf.getSuffixesNotPermitted().addAll(suffixes);

        return conf;
    }

    /**
     * Oracle method !!!
     * This method assumes that the configuration is well-formed and not invalid
     *
     * @param password The password to be checked
     * @param conf     The configuration to make the check against
     * @return True if the password follows the configuration rules; False otherwise
     */
    private boolean passwordRespectsConf(String password, DefaultPasswordRuleConf conf) {
        if (conf.getMinLength() != 0 && password.length() < conf.getMinLength())
            return false;
        if (conf.getMaxLength() != 0 && password.length() > conf.getMaxLength())
            return false;
        boolean nonAlphaNumericFound = false;
        boolean alphanumericFound = false;
        boolean digitFound = false;
        boolean lowercaseFound = false;
        boolean uppercaseFound = false;

        for (Character c : password.toCharArray()) {
            if (!Character.isLetter(c) && !Character.isDigit(c))
                nonAlphaNumericFound = true;
            else if (Character.isDigit(c)) {
                // is considered alphanumeric
                alphanumericFound = true;
                digitFound = true;
            } else if (Character.isLetter(c)) {
                alphanumericFound = true;
                if (Character.isUpperCase(c))
                    uppercaseFound = true;
                else if (Character.isLowerCase(c))
                    lowercaseFound = true;
            }
        }

        if (conf.isNonAlphanumericRequired() && !nonAlphaNumericFound)
            return false;
        if (conf.isAlphanumericRequired() && !alphanumericFound)
            return false;
        if (conf.isDigitRequired() && !digitFound)
            return false;
        if (conf.isLowercaseRequired() && !lowercaseFound)
            return false;
        if (conf.isUppercaseRequired() && !uppercaseFound)
            return false;

        char lastChar = password.toCharArray()[password.length() - 1];
        char firstChar = password.toCharArray()[0];

        // check must start
        if (conf.isMustStartWithNonAlpha()) {
            // both digit and special characters are contemplated
            if (Character.isLetter(firstChar))
                return false;
        }
        if (conf.isMustStartWithDigit()) {
            if (!Character.isDigit(firstChar))
                return false;
        }
        if (conf.isMustStartWithAlpha()) {
            if (!Character.isLetter(firstChar))
                return false;
        }
        // check must end
        if (conf.isMustEndWithNonAlpha() && Character.isLetter(lastChar))
            return false;
        if (conf.isMustEndWithDigit() && !Character.isDigit(lastChar))
            return false;
        if (conf.isMustEndWithAlpha() && !Character.isLetter(lastChar))
            return false;
        // check must not start
        if (conf.isMustntStartWithNonAlpha() && !Character.isLetter(firstChar))
            return false;
        if (conf.isMustntStartWithDigit() && Character.isDigit(firstChar))
            return false;
        if (conf.isMustntStartWithAlpha() && Character.isLetter(firstChar))
            return false;
        // check must not end
        if (conf.isMustntEndWithNonAlpha() && !Character.isLetter(lastChar))
            return false;
        if (conf.isMustntEndWithDigit() && Character.isDigit(lastChar))
            return false;
        if (conf.isMustntEndWithAlpha() && Character.isLetter(lastChar))
            return false;

        // check blacklists
        for (String s : conf.getWordsNotPermitted()) {
            if (password.contains(s))
                return false;
        }
        for (String s : conf.getSchemasNotPermitted()) {
            if (password.contains(s))
                return false;
        }
        for (String s : conf.getPrefixesNotPermitted()) {
            if (password.startsWith(s))
                return false;
        }
        for (String s : conf.getSuffixesNotPermitted()) {
            if (password.endsWith(s))
                return false;
        }

        // test passed
        return true;
    }


    private DefaultPasswordRuleConf mergeConfigurations(List<DefaultPasswordRuleConf> configs) {
        DefaultPasswordRuleConf resultingConf = new DefaultPasswordRuleConf();
        resultingConf.setMinLength(Integer.MIN_VALUE);
        resultingConf.setMaxLength(Integer.MAX_VALUE);


        for (DefaultPasswordRuleConf conf : configs) {
            int actualMinLen = resultingConf.getMinLength();
            int actualMaxLen = resultingConf.getMaxLength();
            if (conf.getMinLength() == 0 && actualMinLen == Integer.MIN_VALUE)
                resultingConf.setMinLength(conf.getMinLength());
            else if (conf.getMinLength() > actualMinLen)
                resultingConf.setMinLength(conf.getMinLength());

            if (conf.getMaxLength() == 0 && actualMaxLen == Integer.MAX_VALUE)
                resultingConf.setMaxLength(conf.getMaxLength());
            else if (conf.getMaxLength() < actualMaxLen)
                resultingConf.setMaxLength(conf.getMaxLength());

            if (conf.isNonAlphanumericRequired())
                resultingConf.setNonAlphanumericRequired(true);
            if (conf.isAlphanumericRequired())
                resultingConf.setAlphanumericRequired(true);
            if (conf.isDigitRequired())
                resultingConf.setDigitRequired(true);
            if (conf.isLowercaseRequired())
                resultingConf.setLowercaseRequired(true);
            if (conf.isUppercaseRequired())
                resultingConf.setUppercaseRequired(true);

            if (conf.isMustStartWithDigit())
                resultingConf.setMustStartWithDigit(true);
            if (conf.isMustntStartWithDigit())
                resultingConf.setMustntStartWithDigit(true);
            if (conf.isMustEndWithDigit())
                resultingConf.setMustEndWithDigit(true);
            if (conf.isMustntEndWithDigit())
                resultingConf.setMustntEndWithDigit(true);
            if (conf.isMustStartWithNonAlpha())
                resultingConf.setMustStartWithNonAlpha(true);
            if (conf.isMustntStartWithNonAlpha())
                resultingConf.setMustntStartWithNonAlpha(true);
            if (conf.isMustStartWithAlpha())
                resultingConf.setMustStartWithAlpha(true);
            if (conf.isMustntStartWithAlpha())
                resultingConf.setMustntStartWithAlpha(true);
            if (conf.isMustEndWithNonAlpha())
                resultingConf.setMustEndWithNonAlpha(true);
            if (conf.isMustntEndWithNonAlpha())
                resultingConf.setMustntEndWithNonAlpha(true);
            if (conf.isMustEndWithAlpha())
                resultingConf.setMustEndWithAlpha(true);
            if (conf.isMustntEndWithAlpha())
                resultingConf.setMustntEndWithAlpha(true);

            resultingConf.getWordsNotPermitted().addAll(conf.getWordsNotPermitted());
            resultingConf.getSchemasNotPermitted().addAll(conf.getSchemasNotPermitted());
            resultingConf.getPrefixesNotPermitted().addAll(conf.getPrefixesNotPermitted());
            resultingConf.getSuffixesNotPermitted().addAll(conf.getSuffixesNotPermitted());

        }

        return resultingConf;
    }

    /**
     * Check if the configurations are not compatible and so
     * an exception is expected.
     *
     * @return True if the exception is expected; False otherwise.
     */
    private boolean isExpectedException(List<DefaultPasswordRule> rules) {

        List<DefaultPasswordRuleConf> configs = new ArrayList<>();

        for (DefaultPasswordRule rule : rules) {
            DefaultPasswordRuleConf c = (DefaultPasswordRuleConf) rule.getConf();
            configs.add(c);
        }

        DefaultPasswordRuleConf resultingConf = mergeConfigurations(configs);

        return isInvalidConfiguration(resultingConf);
    }

    /**
     * Return true if the configuration is NOT valid. False otherwise.
     *
     * @param conf The configuration to be checked.
     * @return True if it's invalid
     */
    private boolean isInvalidConfiguration(DefaultPasswordRuleConf conf) {
        // check sizes
        if (conf.getMinLength() < 0 || conf.getMaxLength() < 0)
            return true;
        if (conf.getMaxLength() != 0 && conf.getMaxLength() < conf.getMinLength()) {
            // if maxLength is zero it means no limit set, so it's not invalid
            return true;
        }

        // check opposite startWith/notStartWith or endWith/notEndWith
        if (conf.isMustStartWithDigit() && conf.isMustntStartWithDigit())
            return true;
        if (conf.isMustStartWithNonAlpha() && conf.isMustntStartWithNonAlpha())
            return true;
        if (conf.isMustStartWithAlpha() && conf.isMustntStartWithAlpha())
            return true;
        if (conf.isMustEndWithDigit() && conf.isMustntEndWithDigit())
            return true;
        if (conf.isMustEndWithNonAlpha() && conf.isMustntEndWithNonAlpha())
            return true;
        if (conf.isMustEndWithAlpha() && conf.isMustntEndWithAlpha())
            return true;

        // check combination of them (take into account that digit and nonAlpha are compatible ->
        // digits are considered a subset of nonAlphas)
        if (conf.isMustStartWithAlpha() && conf.isMustStartWithNonAlpha())
            return true;
        if (conf.isMustStartWithAlpha() && conf.isMustStartWithDigit())
            return true;
        if (conf.isMustEndWithAlpha() && conf.isMustEndWithDigit())
            return true;
        if (conf.isMustEndWithAlpha() && conf.isMustEndWithNonAlpha())
            return true;

        // if the password must not start/end with digit neither alpha neither nonAlpha
        // then with what it's about to start/end? :)
        if (conf.isMustntStartWithDigit() && conf.isMustntStartWithNonAlpha() && conf.isMustntStartWithAlpha())
            return true;
        if (conf.isMustntEndWithDigit() && conf.isMustntEndWithNonAlpha() && conf.isMustntEndWithAlpha())
            return true;

        // total check passed ... phew
        return false;
    }


    @Test
    public void testGeneratePassword() {
        boolean testPassed = true;
        boolean expectedException = false;
        if (rules != null)
            expectedException = isExpectedException(rules);
        try {
            // method under test
            String generatedPassword = defaultPasswordGenerator.generate(policies);
            System.out.println(generatedPassword);

            if (rules != null) {
                List<DefaultPasswordRuleConf> configs = new ArrayList<>();
                for (DefaultPasswordRule rule : rules) {
                    configs.add((DefaultPasswordRuleConf) rule.getConf());
                }

                // configuration obtained merging all others
                DefaultPasswordRuleConf mergedConfiguration = mergeConfigurations(configs);
                testPassed = passwordRespectsConf(generatedPassword, mergedConfiguration);

            } else if (policies != null && policies.isEmpty()) {
                // default configuration
                testPassed = passwordRespectsConf(generatedPassword, new DefaultPasswordRuleConf());
            }

            // at this point, if an exception was expected, it has not been triggered
            if (expectedException)
                testPassed = false;

        } catch (InvalidPasswordRuleConf | NegativeArraySizeException | ArrayIndexOutOfBoundsException e) {
            testPassed = expectedException;
            System.out.println("test passed:" + testPassed);
            System.out.println("expected exception:" + expectedException);
            System.out.println(e.getClass().toString() + ":\t" + e.getMessage());
        } catch (NullPointerException e) {
            System.out.println("null");
            // this verifies only if policies == null, but this never happens in reality, so test is passed
            if (policies == null)
                testPassed = true;
            else
                testPassed = false;
        }

        Assert.assertTrue(testPassed);
    }

    @After
    public void reMock() {
        im.reset();
    }


    @Test
    public void testGenerateWithExternalResource() {

        boolean expectedException = false;
        boolean testPassed = true;

        DefaultPasswordGenerator generator = new DefaultPasswordGenerator();

        List<DefaultPasswordRule> myRule = null;

        if (this.rules != null && !this.rules.isEmpty()) {
            myRule = new ArrayList<>();
            myRule.add(this.rules.get(0));
        }
        if (myRule != null){
            expectedException = isExpectedException(myRule);
        }
        try {
            // method under test (this time with ExternalResource)
            String generatedPassword = defaultPasswordGenerator.generate(externalResource);
            if (myRule != null && !myRule.isEmpty()) {
                // configuration of the rule (is always a single rule)
                DefaultPasswordRuleConf confToTest = (DefaultPasswordRuleConf) myRule.get(0).getConf();
                testPassed = passwordRespectsConf(generatedPassword, confToTest);

            } else if (externalResource == null || externalResource.getPasswordPolicy() == null) {
                // default configuration
                testPassed = passwordRespectsConf(generatedPassword, new DefaultPasswordRuleConf());
            }

            // at this point, if an exception was expected, it has not been triggered
            if (expectedException)
                testPassed = false;

        } catch (InvalidPasswordRuleConf | NegativeArraySizeException | ArrayIndexOutOfBoundsException e) {
            testPassed = expectedException;
        } catch (NullPointerException e) {
            System.out.println("null");
            // this verifies only if policies == null, but this never happens in reality, so test is passed
            if (policies == null)
                testPassed = true;
            else
                testPassed = false;
        }

        Assert.assertTrue(testPassed);
    }


    /**
     * Enumeration to identify different test cases
     * and be able to build different password rules
     * configured as needed
     */
    public enum PoliciesType {
        NULL, EMPTY, VALID,
        SIZE_BOTH_NEG, ONLY_MAX_LEN_NEG, BOTH_SIZE_ZERO, ONLY_MAX_SIZE_ZERO, SIZE_BOTH_TEN, MIN_SIZE_BIGGER_TEN,
        START_AND_NOT_WITH_DIGIT, END_AND_NOT_WITH_DIGIT, START_AND_NOT_WITH_NON_ALPHA, START_AND_NOT_WITH_ALPHA,
        END_AND_NOT_WITH_NON_ALPHA, END_AND_NOT_WITH_ALPHA,
        START_WITH_DIGIT_AND_NON_ALPHA, START_WITH_DIGIT_AND_ALPHA, START_WITH_ALPHA_AND_NON_ALPHA, START_WITH_ALL,
        END_WITH_DIGIT_AND_NON_ALPHA, END_WITH_DIGIT_AND_ALPHA, END_WITH_ALPHA_AND_NON_ALPHA, END_WITH_ALL,
        NOT_START_WITH_ALL, NOT_END_WITH_ALL

    }
}
