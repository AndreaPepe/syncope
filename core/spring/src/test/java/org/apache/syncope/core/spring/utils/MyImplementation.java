package org.apache.syncope.core.spring.utils;

import org.apache.syncope.common.lib.types.ImplementationEngine;
import org.apache.syncope.core.persistence.api.entity.Implementation;

public class MyImplementation implements Implementation {
    @Override
    public String getKey() {
        return null;
    }

    @Override
    public ImplementationEngine getEngine() {
        return null;
    }

    @Override
    public void setEngine(ImplementationEngine engine) {

    }

    @Override
    public String getType() {
        return null;
    }

    @Override
    public void setType(String type) {

    }

    @Override
    public String getBody() {
        return null;
    }

    @Override
    public void setBody(String body) {

    }

    @Override
    public void setKey(String key) {

    }
}
