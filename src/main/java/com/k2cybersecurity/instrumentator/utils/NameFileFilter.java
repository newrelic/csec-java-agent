package com.k2cybersecurity.instrumentator.utils;

import org.apache.commons.io.filefilter.AbstractFileFilter;
import org.apache.commons.lang3.StringUtils;

import java.io.File;

public class NameFileFilter extends AbstractFileFilter {

    private String namePrefix;

    public NameFileFilter(String namePrefix) {
        this.namePrefix = namePrefix;
    }

    @Override
    public boolean accept(File dir, String name) {
        return StringUtils.startsWith(name, namePrefix);
    }
}