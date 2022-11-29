
package com.newrelic.agent.security.schema.policy;

import java.util.Objects;
public class Probing {

    private Integer interval = 1;
    private Integer batchSize = 10;

    /**
     * No args constructor for use in serialization
     */
    public Probing() {
    }

    /**
     * @param interval
     * @param batchSize
     */
    public Probing(Integer interval, Integer batchSize) {
        super();
        this.interval = interval;
        this.batchSize = batchSize;
    }

    public Integer getInterval() {
        return interval;
    }

    public void setInterval(Integer interval) {
        this.interval = interval;
    }

    public Integer getBatchSize() {
        return batchSize;
    }

    public void setBatchSize(Integer batchSize) {
        this.batchSize = batchSize;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Probing probing = (Probing) o;
        return Objects.equals(interval, probing.interval) &&
                Objects.equals(batchSize, probing.batchSize);
    }

    @Override
    public int hashCode() {
        return Objects.hash(interval, batchSize);
    }
}
