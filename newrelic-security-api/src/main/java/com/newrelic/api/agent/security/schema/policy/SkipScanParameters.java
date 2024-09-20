package com.newrelic.api.agent.security.schema.policy;

import java.util.ArrayList;
import java.util.List;

public class SkipScanParameters {

    private List<String> header = new ArrayList<>();

    private List<String> query = new ArrayList<>();

    private List<String> body = new ArrayList<>();

    public SkipScanParameters() {
    }

    public List<String> getHeader() {
        return header;
    }

    public List<String> getQuery() {
        return query;
    }

    public List<String> getBody() {
        return body;
    }

    public void setHeader(List<String> header) {
        this.header = header;
    }

    public void setQuery(List<String> query) {
        this.query = query;
    }

    public void setBody(List<String> body) {
        this.body = body;
    }

    public void addHeader(String header) {
        this.header.add(header);
    }

    public void addQuery(String query) {
        this.query.add(query);
    }

    public void addBody(String body) {
        this.body.add(body);
    }
}
