package com.newrelic.agent.security.instrumentation.grpc1220.processor;

import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;

public class CustomFutureTask<V> extends FutureTask<V> {

    private Callable<V> callable;
    private int hashcode = -1;

    public CustomFutureTask(Callable<V> callable) {
        super(callable);
        this.callable = callable;
        this.hashcode = this.callable.hashCode();
    }

    public CustomFutureTask(Runnable runnable, V result) {
        super(runnable, result);
        this.callable = Executors.callable(runnable, result);
        this.hashcode = runnable.hashCode();
    }

    public Callable<V> getTask() {
        return this.callable;
    }

    @Override
    public int hashCode() {
        return this.hashcode;
    }

    @Override
    public boolean equals(Object obj) {
        return this.hashCode() == obj.hashCode();
    }
}
