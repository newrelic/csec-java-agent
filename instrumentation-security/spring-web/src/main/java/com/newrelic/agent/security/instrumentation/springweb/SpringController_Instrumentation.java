package com.newrelic.agent.security.instrumentation.springweb;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.WeaveIntoAllMethods;
import com.newrelic.api.agent.weaver.WeaveWithAnnotation;

@WeaveWithAnnotation(annotationClasses = {
        "org.springframework.stereotype.Controller",
        "org.springframework.web.bind.annotation.RestController"},
        type = MatchType.ExactClass)
public class SpringController_Instrumentation {

    @WeaveWithAnnotation(annotationClasses = {
            "org.springframework.web.bind.annotation.RequestMapping",
            "org.springframework.web.bind.annotation.PatchMapping",
            "org.springframework.web.bind.annotation.PutMapping",
            "org.springframework.web.bind.annotation.GetMapping",
            "org.springframework.web.bind.annotation.PostMapping",
            "org.springframework.web.bind.annotation.DeleteMapping",
            "org.springframework.graphql.data.method.annotation.MutationMapping",
            "org.springframework.graphql.data.method.annotation.QueryMapping",
            "org.springframework.graphql.data.method.annotation.SchemaMapping",
            "org.springframework.graphql.data.method.annotation.SubscriptionMapping",
            "org.springframework.graphql.data.method.annotation.BatchMapping"
    })
    @WeaveIntoAllMethods
    private static void requestMapping() {
        ServletHelper.setFoundAnnotatedUserLevelServiceMethod(false);
        ServletHelper.registerUserLevelCode("spring-annotation");
        ServletHelper.setFoundAnnotatedUserLevelServiceMethod(true);
    }

}
