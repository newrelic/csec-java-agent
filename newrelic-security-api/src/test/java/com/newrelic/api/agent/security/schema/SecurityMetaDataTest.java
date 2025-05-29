package com.newrelic.api.agent.security.schema;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SecurityMetaDataTest {

    @Test
    public void customAttTestNull() {
        assertNull(new SecurityMetaData().getCustomAttribute("not-exists", this.getClass()));
        assertNull(new SecurityMetaData().getCustomAttribute("not-exists", String.class));
    }
    @Test
    public void customAttTest() {
        String data = "data";
        SecurityMetaData metaData = new SecurityMetaData();
        metaData.addCustomAttribute("exists",data);
        String obj = metaData.getCustomAttribute("exists", String.class);
        assertNotNull(obj);
        assertEquals(data, obj);
        metaData.removeCustomAttribute("exists");
        assertNull(metaData.getCustomAttribute("exists", String.class));
    }
    @Test
    public void customAttTest1() {
        String data = "data";
        SecurityMetaData metaData = new SecurityMetaData();
        metaData.addCustomAttribute("exists",data);
        assertThrows(ClassCastException.class, () -> metaData.getCustomAttribute("exists", Integer.class));
    }
}
