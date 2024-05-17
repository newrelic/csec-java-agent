package com.newrelic.agent.security.intcodeagent.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.newrelic.api.agent.security.schema.HttpRequest;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class FuzzRequestBean extends com.newrelic.api.agent.security.schema.FuzzRequestBean implements Serializable {
}
