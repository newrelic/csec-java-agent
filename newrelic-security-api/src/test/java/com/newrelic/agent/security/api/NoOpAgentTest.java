/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.api;

//import org.junit.Test;
//
//import java.util.logging.Level;
//
//import static org.junit.Assert.assertEquals;
//import static org.junit.Assert.assertFalse;
//import static org.junit.Assert.assertNotNull;
//import static org.junit.Assert.assertNull;

/**
 * This test covers what happens when users call our APIs when running without the agent.
 */
public class NoOpAgentTest {
//
//    @Test
//    public void testNoOpPublicApiTransactionDefaults() {
//
//        assertNotNull(NewRelicSecurity.getAgent().getTransaction());
//        checkTransactionDefaults(NewRelicSecurity.getAgent().getTransaction());
//    }
//
//    @Test
//    public void testNoOpTracedMethod()  {
//        assertNotNull(NewRelicSecurity.getAgent().getTracedMethod().getMetricName());
//        assertNotNull(NewRelicSecurity.getAgent().getTracedMethod().getMetricName());
//    }
//
//    @Test
//    public void testNoOpConfig()  {
//        assertNull(NewRelicSecurity.getAgent().getConfig().getValue("anyKey"));
//        assertEquals("defaultValue", NewRelicSecurity.getAgent().getConfig().getValue("someKey", "defaultValue"));
//    }
//
//    @Test
//    public void testNoOpLogger()  {
//        assertFalse(NewRelicSecurity.getAgent().getLogger().isLoggable(Level.OFF));
//        assertFalse(NewRelicSecurity.getAgent().getLogger().isLoggable(Level.WARNING));
//        assertFalse(NewRelicSecurity.getAgent().getLogger().isLoggable(Level.SEVERE));
//        assertFalse(NewRelicSecurity.getAgent().getLogger().isLoggable(Level.ALL));
//        assertFalse(NewRelicSecurity.getAgent().getLogger().isLoggable(Level.INFO));
//        assertFalse(NewRelicSecurity.getAgent().getLogger().isLoggable(Level.FINER));
//        assertFalse(NewRelicSecurity.getAgent().getLogger().isLoggable(Level.FINEST));
//    }
//
//
//
//    public void checkTransactionDefaults(Transaction transaction) {
//        assertFalse(transaction.setTransactionName(TransactionNamePriority.CUSTOM_HIGH, true, "", ""));
//        assertFalse(transaction.isTransactionNameSet());
//        assertFalse(transaction.markResponseSent());
//
//        assertNotNull(transaction.getTracedMethod());
//
//        assertNotNull(transaction.getToken());
//        assertFalse(transaction.getToken().link());
//        assertFalse(transaction.getToken().expire());
//        assertFalse(transaction.getToken().linkAndExpire());
//        assertFalse(transaction.getToken().isActive());
//
//        assertNull(transaction.getRequestMetadata());
//        assertNull(transaction.getResponseMetadata());
//
//    }
}

