package com.newrelic.csec.validator.scanner;

import java.io.Serializable;

public class DeltaClass implements Serializable {

    private static final long serialVersionUID = 5220788560470736671L;

    public String field0;

    public DeltaClass(String field0) {
        this.field0 = field0;
    }

    public String getField0() {
        return field0;
    }

    public void setField0(String field0) {
        this.field0 = field0;
    }
}
