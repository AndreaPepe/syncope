package org.apache.syncope.core.spring.utils;

import org.apache.syncope.common.lib.types.ConnConfProperty;
import org.apache.syncope.common.lib.types.ConnectorCapability;
import org.apache.syncope.common.lib.types.TraceLevel;
import org.apache.syncope.core.persistence.api.entity.AnyType;
import org.apache.syncope.core.persistence.api.entity.ConnInstance;
import org.apache.syncope.core.persistence.api.entity.Implementation;
import org.apache.syncope.core.persistence.api.entity.policy.*;
import org.apache.syncope.core.persistence.api.entity.resource.ExternalResource;
import org.apache.syncope.core.persistence.api.entity.resource.OrgUnit;
import org.apache.syncope.core.persistence.api.entity.resource.Provision;
import org.identityconnectors.framework.common.objects.ObjectClass;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public class MyExternalResource implements ExternalResource {

    PasswordPolicy policy;

    public MyExternalResource(PasswordPolicy policy){
        this.policy = policy;
    }

    @Override
    public String getKey() {
        return null;
    }

    @Override
    public void setKey(String key) {

    }

    @Override
    public ConnInstance getConnector() {
        return null;
    }

    @Override
    public void setConnector(ConnInstance connector) {

    }

    @Override
    public Set<ConnConfProperty> getConfOverride() {
        return null;
    }

    @Override
    public void setConfOverride(Set<ConnConfProperty> confOverride) {

    }

    @Override
    public boolean isOverrideCapabilities() {
        return false;
    }

    @Override
    public void setOverrideCapabilities(boolean overrideCapabilities) {

    }

    @Override
    public Set<ConnectorCapability> getCapabilitiesOverride() {
        return null;
    }

    @Override
    public AccountPolicy getAccountPolicy() {
        return null;
    }

    @Override
    public void setAccountPolicy(AccountPolicy accountPolicy) {

    }

    @Override
    public PasswordPolicy getPasswordPolicy() {
        return this.policy;
    }

    @Override
    public void setPasswordPolicy(PasswordPolicy passwordPolicy) {
        this.policy = passwordPolicy;
    }

    @Override
    public PropagationPolicy getPropagationPolicy() {
        return null;
    }

    @Override
    public void setPropagationPolicy(PropagationPolicy propagationPolicy) {

    }

    @Override
    public PullPolicy getPullPolicy() {
        return null;
    }

    @Override
    public void setPullPolicy(PullPolicy pullPolicy) {

    }

    @Override
    public PushPolicy getPushPolicy() {
        return null;
    }

    @Override
    public Implementation getProvisionSorter() {
        return null;
    }

    @Override
    public void setProvisionSorter(Implementation provisionSorter) {

    }

    @Override
    public void setPushPolicy(PushPolicy pushPolicy) {

    }

    @Override
    public TraceLevel getCreateTraceLevel() {
        return null;
    }

    @Override
    public void setCreateTraceLevel(TraceLevel createTraceLevel) {

    }

    @Override
    public TraceLevel getUpdateTraceLevel() {
        return null;
    }

    @Override
    public void setUpdateTraceLevel(TraceLevel updateTraceLevel) {

    }

    @Override
    public TraceLevel getDeleteTraceLevel() {
        return null;
    }

    @Override
    public void setDeleteTraceLevel(TraceLevel deleteTraceLevel) {

    }

    @Override
    public TraceLevel getProvisioningTraceLevel() {
        return null;
    }

    @Override
    public void setProvisioningTraceLevel(TraceLevel provisioningTraceLevel) {

    }

    @Override
    public boolean add(Implementation propagationAction) {
        return false;
    }

    @Override
    public List<? extends Implementation> getPropagationActions() {
        return null;
    }

    @Override
    public Integer getPropagationPriority() {
        return null;
    }

    @Override
    public void setPropagationPriority(Integer priority) {

    }

    @Override
    public boolean isEnforceMandatoryCondition() {
        return false;
    }

    @Override
    public void setEnforceMandatoryCondition(boolean enforce) {

    }

    @Override
    public boolean isRandomPwdIfNotProvided() {
        return false;
    }

    @Override
    public void setRandomPwdIfNotProvided(boolean condition) {

    }

    @Override
    public boolean add(Provision provision) {
        return false;
    }

    @Override
    public Optional<? extends Provision> getProvision(String anyType) {
        return Optional.empty();
    }

    @Override
    public Optional<? extends Provision> getProvision(AnyType anyType) {
        return Optional.empty();
    }

    @Override
    public Optional<? extends Provision> getProvision(ObjectClass objectClass) {
        return Optional.empty();
    }

    @Override
    public List<? extends Provision> getProvisions() {
        return null;
    }

    @Override
    public OrgUnit getOrgUnit() {
        return null;
    }

    @Override
    public void setOrgUnit(OrgUnit orgUnit) {

    }
}
