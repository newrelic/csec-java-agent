package com.newrelic.api.agent.security.utils;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.helper.Log4JStrSubstitutor;

public class UserDataTranslationHelper {

    public static void placeJNDIAdditionalTemplateData() {
        Log4JStrSubstitutor substitutor = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(getAttributeName(Log4JStrSubstitutor.class.getName()), Log4JStrSubstitutor.class);
        String variableValue = StringUtils.EMPTY;
        if(substitutor != null && substitutor.getBuf() != null){
            variableValue = StringUtils.substring(substitutor.getBuf().toString(), substitutor.getStartPos(), substitutor.getEndPos());
        }

        if(StringUtils.isNotBlank(variableValue) && !StringUtils.equals(variableValue, substitutor.getVariableName())){
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().getUserDataTranslationMap().put(substitutor.getVariableName(), variableValue);
        }
    }

    public static String getAttributeName(String identifier) {
        return Thread.currentThread().getId() + identifier;
    }
}
