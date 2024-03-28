package com.nr.agent.security.instrumentation.spring.webmvc;/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class TestMappings {

    @RequestMapping(value = "/requestMapping", method = RequestMethod.GET)
    public String testRequest() {
        return "From Request Mapping";
    }

    @RequestMapping(value = "/postMapping", method = RequestMethod.POST)
    public String testPost() {
        return "From Post Mapping";
    }

    @RequestMapping(value = "/putMapping", method = RequestMethod.PUT)
    public String testPut() {
        return "From Put Mapping";
    }

    @RequestMapping(value = "/deleteMapping", method = RequestMethod.DELETE)
    public String testDelete() {
        return "From Delete Mapping";
    }
}
