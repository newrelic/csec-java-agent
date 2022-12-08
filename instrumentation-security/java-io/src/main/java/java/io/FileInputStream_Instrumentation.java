/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.javaio.FileHelper;

@Weave(type = MatchType.ExactClass, originalName = "java.io.FileInputStream")
public abstract class FileInputStream_Instrumentation {

    private void open(String name) throws FileNotFoundException {
        AbstractOperation operation = preprocessSecurityHook(name);
        Weaver.callOriginal();
        registerExitOperation(operation);
    }

    private void registerExitOperation(AbstractOperation operation) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){}
    }

    private AbstractOperation preprocessSecurityHook(String filename) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
                    || filename == null || filename.trim().isEmpty()
            ) {
                return null;
            }
            String filePath = new File(filename).getAbsolutePath();
            FileOperation operation = new FileOperation(filePath,
                    FileOutputStream_Instrumentation.class.getName(), FileHelper.FILEOUTPUTSTREAM_OPEN, false);
            FileHelper.createEntryOfFileIntegrity(filePath, FileOutputStream_Instrumentation.class.getName(), FileHelper.FILEOUTPUTSTREAM_OPEN);
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                e.printStackTrace();
                throw e;
            }
        }
        return null;
    }
}
