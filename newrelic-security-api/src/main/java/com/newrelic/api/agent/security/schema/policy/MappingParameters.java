package com.newrelic.api.agent.security.schema.policy;

import com.newrelic.api.agent.security.schema.annotations.JsonProperty;

public class MappingParameters {

    private MappingParameter header;

    private MappingParameter body;

    private MappingParameter query;

    private MappingParameter path;

    public MappingParameters() {
        this.header = new MappingParameter();
        this.body = new MappingParameter();
        this.query = new MappingParameter();
        this.path = new MappingParameter();
    }

    public MappingParameters(MappingParameter header, MappingParameter body, MappingParameter query, MappingParameter path) {
        this.header = header;
        this.body = body;
        this.query = query;
        this.path = path;
    }

    public MappingParameter getHeader() {
        return header;
    }

    public void setHeader(MappingParameter header) {
        this.header = header;
    }

    public MappingParameter getBody() {
        return body;
    }

    public void setBody(MappingParameter body) {
        this.body = body;
    }

    public MappingParameter getQuery() {
        return query;
    }

    public void setQuery(MappingParameter query) {
        this.query = query;
    }

    public MappingParameter getPath() {
        return path;
    }

    public void setPath(MappingParameter path) {
        this.path = path;
    }
}
