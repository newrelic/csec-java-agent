package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

public class CallbackUtilsTest {

    @Test
    public void checkForReflectedXSSTest() {
        HashSet<String> expected = new HashSet<>();
        expected.add("");
        Assert.assertEquals(expected, CallbackUtils.checkForReflectedXSS(new HttpRequest(), new HttpResponse()));
    }
    @Test
    public void checkForReflectedXSS1Test() {
        HashSet<String> expected = new HashSet<>();
        expected.add("");
        Assert.assertEquals(expected, CallbackUtils.checkForReflectedXSS(new HttpRequest(), new HttpResponse()));
    }
    @Test
    public void checkForReflectedXSS2Test() {
        HashSet<String> expected = new HashSet<>();
        expected.add("");
        Assert.assertEquals(expected, CallbackUtils.checkForReflectedXSS(new HttpRequest(), new HttpResponse()));
    }

    @Test
    public void urlDecodeTest() {
        Assert.assertEquals(StringUtils.EMPTY, CallbackUtils.urlDecode(StringUtils.EMPTY));
        Assert.assertEquals("  ", CallbackUtils.urlDecode("  "));
        Assert.assertEquals("<script>", CallbackUtils.urlDecode("<script>"));
        Assert.assertEquals("<script>", CallbackUtils.urlDecode("%3Cscript%3E"));
    }
    @Test
    public void getXSSConstructsTest() {
        Set<String> actual = CallbackUtils.getXSSConstructs("<script>some</script>");
        Set<String> expected = new HashSet<>(); expected.add("<script>some");
        Assert.assertNotNull(actual);
        Assert.assertEquals(1, actual.size());
        Assert.assertEquals(expected, actual);
    }
    @Test
    public void getXSSConstructs1Test() {
        Set<String> actual = CallbackUtils.getXSSConstructs("<script>alert(1)</script>");
        Set<String> expected = new HashSet<>(); expected.add("<script>alert(1)");
        Assert.assertNotNull(actual);
        Assert.assertEquals(1, actual.size());
        Assert.assertEquals(expected, actual);
    }
}
