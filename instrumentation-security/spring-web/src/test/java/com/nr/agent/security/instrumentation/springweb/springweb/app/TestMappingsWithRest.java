package com.nr.agent.security.instrumentation.springweb.springweb.app;

import org.springframework.graphql.data.method.annotation.BatchMapping;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.data.method.annotation.SchemaMapping;
import org.springframework.graphql.data.method.annotation.SubscriptionMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestMappingsWithRest {

    @RequestMapping(value = "/requestMapping", method = RequestMethod.GET)
    public String testRequest() {
        return "From Request RestMapping";
    }

    @GetMapping(value = "/getMapping")
    public String testGet() {
        return "From Get RestMapping";
    }

    @PostMapping(value = "/postMapping")
    public String testPost() {
        return "From Post RestMapping";
    }

    @PatchMapping(value = "/patchMapping")
    public String testPatch() {
        return "From Patch RestMapping";
    }

    @PutMapping(value = "/putMapping")
    public String testPut() {
        return "From Put RestMapping";
    }

    @DeleteMapping(value = "/deleteMapping")
    public String testDelete() {
        return "From Delete RestMapping";
    }

    @MutationMapping
    public void testMutation() {
        // mutation mapping
    }

    @QueryMapping
    public void testQuery() {
        // Query mapping
    }

    @SchemaMapping
    public void testSchemaMapping() {
        // SchemaMapping
    }

    @SubscriptionMapping
    public void testSubscriptionMapping() {
        // SubscriptionMapping
    }

    @BatchMapping
    public void testBatchMapping() {
        // BatchMapping
    }

}
