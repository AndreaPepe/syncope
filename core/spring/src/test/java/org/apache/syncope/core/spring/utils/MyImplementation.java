package org.apache.syncope.core.spring.utils;

import org.apache.syncope.common.lib.types.ImplementationEngine;
import org.apache.syncope.core.persistence.api.entity.Implementation;

public class MyImplementation implements Implementation {
    ImplementationEngine engine;
    String body;

    private static final String TABLE = "Implementation";
    private static final long serialVersionUID = 1L;

    @Override
    public String getKey() {
        return null;
    }

    @Override
    public ImplementationEngine getEngine() {
        return engine;
    }

    @Override
    public void setEngine(ImplementationEngine engine) {
        this.engine = engine;
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
        return this.body;
    }

    @Override
    public void setBody(String body) {
        this.body = body;
    }

    @Override
    public void setKey(String key) {

    }
}
