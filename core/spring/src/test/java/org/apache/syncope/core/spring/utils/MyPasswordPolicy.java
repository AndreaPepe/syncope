package org.apache.syncope.core.spring.utils;

import org.apache.syncope.core.persistence.api.entity.Implementation;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;

import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;

public class MyPasswordPolicy implements PasswordPolicy {

    @NotNull
    private Boolean allowNullPassword = false;

    private int historyLength;

    private List<Implementation> rules = new ArrayList<>();

    @Override
    public String getKey() {
        return null;
    }

    @Override
    public boolean isAllowNullPassword() {
        return allowNullPassword;
    }

    @Override
    public void setAllowNullPassword(boolean allowNullPassword) {
        this.allowNullPassword = allowNullPassword;
    }

    @Override
    public int getHistoryLength() {
        return historyLength;
    }

    @Override
    public void setHistoryLength(int historyLength) {
        this.historyLength = historyLength;
    }

    @Override
    public boolean add(Implementation rule) {
        if (!rules.contains(rule)) {
            rules.add(rule);
        }
        return true;
    }

    @Override
    public List<? extends Implementation> getRules() {
        return rules;
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public void setName(String name) {

    }










}
