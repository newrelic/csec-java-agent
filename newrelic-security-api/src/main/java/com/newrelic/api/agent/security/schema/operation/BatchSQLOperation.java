package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class BatchSQLOperation extends AbstractOperation {

    private List<SQLOperation> operations;

    public BatchSQLOperation(String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.SQL_DB_COMMAND);
        this.operations = new ArrayList<>();
    }

    public List<SQLOperation> getOperations() {
        return operations;
    }

    public void addOperation(SQLOperation operation) {
        if(operation != null && !operation.isEmpty()) {
            this.operations.add(operation);
        }
    }

    @Override
    public boolean isEmpty() {
        return this.operations.isEmpty();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        BatchSQLOperation that = (BatchSQLOperation) o;
        return operations.equals(that.operations);
    }

    public void clearOperation() {
        if(operations != null && !operations.isEmpty()) {
            this.operations.clear();
        }
    }

    @Override
    public int hashCode() {
        return Objects.hash(operations);
    }
}

