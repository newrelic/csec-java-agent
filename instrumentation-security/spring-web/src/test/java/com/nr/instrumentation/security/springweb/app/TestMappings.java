package com.nr.instrumentation.security.springweb.app;/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class TestMappings {

    @RequestMapping(value = "/requestMapping", method = RequestMethod.GET)
    public String testRequest() {
        return "From Request Mapping";
    }

    @GetMapping(value = "/getMapping")
    public String testGet() {
        return "From Get Mapping";
    }

    @PostMapping(value = "/postMapping")
    public String testPost() {
        return "From Post Mapping";
    }

    @PatchMapping(value = "/patchMapping")
    public String testPatch() {
        return "From Patch Mapping";
    }

    @PutMapping(value = "/putMapping")
    public String testPut() {
        return "From Put Mapping";
    }

    @DeleteMapping(value = "/deleteMapping")
    public String testDelete() {
        return "From Delete Mapping";
    }
}
