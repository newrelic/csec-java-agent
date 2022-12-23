/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.deps.com.google.common.collect.Iterables;
import com.newrelic.weave.violation.WeaveViolation;
import com.newrelic.weave.weavepackage.PackageValidationResult;
import com.newrelic.weave.weavepackage.WeavePackage;
import com.newrelic.weave.weavepackage.WeavePackageLifetimeListener;
import org.junit.Assert;

import java.util.List;

/**
 * Listens for weave package validated events and fails tests if weave violations occur.
 */
public class FailingWeavePackageListener implements WeavePackageLifetimeListener {

    @Override
    public void registered(WeavePackage weavepackage) {
    }

    @Override
    public void deregistered(WeavePackage weavepackage) {
    }

    @Override
    public void validated(PackageValidationResult packageResult, ClassLoader classloader) {
        if (!packageResult.succeeded()) {
            List<WeaveViolation> violations = packageResult.getViolations();
            String message = String.format("Found %d violations: %s", violations.size(), Iterables.toString(
                    violations));
            Assert.fail(message);
        }
    }
}
