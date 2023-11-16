package com.newrelic.api.agent.security.schema;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class StringUtilsTest {
    @Test
    public void testIsNotBlank(){
        Assertions.assertFalse(StringUtils.isNotBlank(StringUtils.EMPTY), "Should return false");
        Assertions.assertFalse(StringUtils.isNotBlank(null), "Should return false");
        Assertions.assertFalse(StringUtils.isNotBlank("  "), "Should return false");
        Assertions.assertTrue(StringUtils.isNotBlank("some"), "Should return true");
        Assertions.assertTrue(StringUtils.isNotBlank(" some "), "Should return true");
    }
    @Test
    public void testIsBlank(){
        Assertions.assertTrue(StringUtils.isBlank(StringUtils.EMPTY), "Should return true");
        Assertions.assertTrue(StringUtils.isBlank(null), "Should return true");
        Assertions.assertTrue(StringUtils.isBlank("  "), "Should return true");
        Assertions.assertFalse(StringUtils.isBlank("some"), "Should return false");
        Assertions.assertFalse(StringUtils.isBlank(" some "), "Should return false");
    }
    @Test
    public void testIsAnyBlank(){
        Assertions.assertTrue(StringUtils.isAnyBlank(StringUtils.EMPTY, null, " "), "Should return true");
        Assertions.assertTrue(StringUtils.isAnyBlank(null, " "), "Should return true");
        Assertions.assertTrue(StringUtils.isAnyBlank(StringUtils.EMPTY, " some"), "Should return true");
        Assertions.assertTrue(StringUtils.isAnyBlank("  ", "some"), "Should return true");
        Assertions.assertFalse(StringUtils.isAnyBlank(" some "), "Should return false");
    }
    @Test
    public void testSubstringBefore(){
        Assertions.assertNull(StringUtils.substringBefore(null, "*"));
        Assertions.assertEquals(StringUtils.EMPTY, StringUtils.substringBefore(StringUtils.EMPTY, "*"));
        Assertions.assertEquals("  ", StringUtils.substringBefore("  ", "*"));
        Assertions.assertEquals( "some", StringUtils.substringBefore("some","a"));
        Assertions.assertEquals("", StringUtils.substringBefore("some ", "s"));
        Assertions.assertEquals(" ", StringUtils.substringBefore(" some ", "s"));
        Assertions.assertEquals(" s", StringUtils.substringBefore(" some ", "o"));
    }
    @Test
    public void testSubstringBeforeLast(){
        Assertions.assertNull(StringUtils.substringBeforeLast(null, "*"));
        Assertions.assertEquals(StringUtils.EMPTY, StringUtils.substringBeforeLast(StringUtils.EMPTY, "*"));
        Assertions.assertEquals("  ", StringUtils.substringBeforeLast("  ", "*"));
        Assertions.assertEquals( "some", StringUtils.substringBeforeLast("some","a"));
        Assertions.assertEquals( "some", StringUtils.substringBeforeLast("some",null));
        Assertions.assertEquals("", StringUtils.substringBeforeLast("some ", "s"));
        Assertions.assertEquals(" ", StringUtils.substringBeforeLast(" some ", "s"));
        Assertions.assertEquals(" s", StringUtils.substringBeforeLast(" some ", "o"));
        Assertions.assertEquals(" s", StringUtils.substringBeforeLast(" somes ", "o"));
    }

    @Test
    public void testSubstring(){
        Assertions.assertNull(StringUtils.substring(null, 0, 0));
        Assertions.assertEquals(StringUtils.EMPTY, StringUtils.substring(StringUtils.EMPTY, 0, 0));
        Assertions.assertEquals("", StringUtils.substring("  ", 0, 0));
        Assertions.assertEquals( "", StringUtils.substring("some",0, 0));
        Assertions.assertEquals( "s", StringUtils.substring("some",0, 1));
        Assertions.assertEquals("o", StringUtils.substring("some ", 1, 2));
        Assertions.assertEquals("me", StringUtils.substring("some", 2, 5));
        Assertions.assertEquals("m", StringUtils.substring("some", -2, -1));
        Assertions.assertEquals("", StringUtils.substring("some", -5, -6));
    }
    @Test
    public void testAppendIfMissing0(){
        String FILES = "files";
        String FILES_EXT = "files.ext";
        Assertions.assertEquals(StringUtils.appendIfMissing(StringUtils.EMPTY, ""), "");
        Assertions.assertEquals(StringUtils.appendIfMissing(StringUtils.EMPTY, "", ""), "");
        Assertions.assertEquals(StringUtils.appendIfMissing(FILES, "", new CharSequence[]{null}), "files");
        Assertions.assertEquals(StringUtils.appendIfMissing(FILES, ".ext", ".txt"), "files.ext");
        Assertions.assertEquals(StringUtils.appendIfMissing(FILES_EXT, ".ext", ""), "files.ext");
        Assertions.assertEquals(StringUtils.appendIfMissing(FILES_EXT, ".Ext", ""), "files.ext");
        Assertions.assertEquals(StringUtils.appendIfMissing(FILES_EXT, ".txt", ".ext"), "files.ext");
        Assertions.assertEquals(StringUtils.appendIfMissing(FILES, ".txt", ".pdf", ".jar"), "files.txt");
    }

    @Test
    public void testAppendIfMissingIgnoreCase(){
        String FILES = "files";
        String FILES_EXT = "files.ext";
        Assertions.assertEquals(StringUtils.appendIfMissingIgnoreCase(StringUtils.EMPTY, ""), "");
        Assertions.assertEquals(StringUtils.appendIfMissingIgnoreCase(StringUtils.EMPTY, "", ""), "");
        Assertions.assertEquals(StringUtils.appendIfMissingIgnoreCase(FILES, "", new CharSequence[]{null}), "files");
        Assertions.assertEquals(StringUtils.appendIfMissingIgnoreCase(FILES, ".ext", ".txt"), "files.ext");
        Assertions.assertEquals(StringUtils.appendIfMissingIgnoreCase(FILES_EXT, ".ext", ""), "files.ext");
        Assertions.assertEquals(StringUtils.appendIfMissingIgnoreCase(FILES_EXT, ".Ext", ""), "files.ext");
        Assertions.assertEquals(StringUtils.appendIfMissingIgnoreCase(FILES_EXT, ".txt", ".ext"), "files.ext");
        Assertions.assertEquals(StringUtils.appendIfMissingIgnoreCase(FILES, ".txt", ".pdf", ".jar"), "files.txt");
    }
    @Test
    public void testIsEmpty(){
        Assertions.assertTrue(StringUtils.isEmpty(StringUtils.EMPTY), "Should return false");
        Assertions.assertTrue(StringUtils.isEmpty(null), "Should return true");
        Assertions.assertFalse(StringUtils.isEmpty("  "), "Should return false");
        Assertions.assertFalse(StringUtils.isEmpty("some"), "Should return false");
        Assertions.assertFalse(StringUtils.isEmpty(" some "), "Should return false");
    }

    @Test
    public void testSplitByWholeSeparatorWorker(){
        Assertions.assertNull(StringUtils.splitByWholeSeparatorWorker(null, "", 1, false), "Should return false");
        Assertions.assertArrayEquals(StringUtils.splitByWholeSeparatorWorker(StringUtils.EMPTY, "", 1, false), new String[]{},"Should return false");
        Assertions.assertTrue(StringUtils.isBlank("  "), "Should return false");
        Assertions.assertFalse(StringUtils.isBlank("some"), "Should return true");
        Assertions.assertFalse(StringUtils.isBlank(" some "), "Should return true");
    }


    @Test
    public void testReplace(){
        String txt = "some";
        Assertions.assertNull(StringUtils.replace(null, null, null), "Should return true");
        Assertions.assertEquals(StringUtils.EMPTY, StringUtils.replace(StringUtils.EMPTY, StringUtils.EMPTY, StringUtils.EMPTY));
        Assertions.assertEquals(txt, StringUtils.replace(txt, StringUtils.EMPTY, StringUtils.EMPTY));
        Assertions.assertEquals("sOMe", StringUtils.replace(txt, "om", "OM"));
        Assertions.assertEquals(txt, StringUtils.replace(txt, "xyz", StringUtils.EMPTY));
        Assertions.assertEquals(StringUtils.EMPTY, StringUtils.replace(StringUtils.EMPTY, StringUtils.EMPTY, StringUtils.EMPTY));
    }
    @Test
    public void testEquals(){
        Assertions.assertTrue(StringUtils.equals(null, null), "Should return true");
        Assertions.assertFalse(StringUtils.equals(null, StringUtils.EMPTY), "Should return false");
        Assertions.assertTrue(StringUtils.equals(StringUtils.EMPTY, StringUtils.EMPTY), "Should return true");
        Assertions.assertTrue(StringUtils.equals("some", "some"), "Should return true");
        Assertions.assertFalse(StringUtils.equals("some", "Some"), "Should return false");
        Assertions.assertFalse(StringUtils.equals("some", "somE"), "Should return false");
    }
    @Test
    public void testEqualsAny(){
        Assertions.assertTrue(StringUtils.equalsAny(null, (CharSequence) null), "Should return true");
        Assertions.assertTrue(StringUtils.equalsAny(null, StringUtils.EMPTY, null), "Should return false");
        Assertions.assertTrue(StringUtils.equalsAny(StringUtils.EMPTY, StringUtils.EMPTY), "Should return true");
        Assertions.assertTrue(StringUtils.equalsAny("some", "some"), "Should return true");
        Assertions.assertFalse(StringUtils.equalsAny("some", "Some"), "Should return false");
        Assertions.assertFalse(StringUtils.equalsAny("some", "somE"), "Should return false");
        Assertions.assertTrue(StringUtils.equalsAny("some", "Some", "some"), "Should return true");
        Assertions.assertTrue(StringUtils.equalsAny("some", "somE", "some"), "Should return true");
    }
    @Test
    public void testStartsWith(){
        Assertions.assertTrue(StringUtils.startsWith(null, (CharSequence) null), "Should return true");
        Assertions.assertFalse(StringUtils.startsWith(null, StringUtils.EMPTY), "Should return false");
        Assertions.assertTrue(StringUtils.startsWith(StringUtils.EMPTY, StringUtils.EMPTY), "Should return true");
        Assertions.assertTrue(StringUtils.startsWith("some", "some"), "Should return true");
        Assertions.assertFalse(StringUtils.startsWith("some", "Some"), "Should return false");
        Assertions.assertTrue(StringUtils.startsWith("something", "some"), "Should return false");
        Assertions.assertFalse(StringUtils.startsWith("something", "thing"), "Should return true");
    }
    @Test
    public void testStartsWithAny(){
        Assertions.assertTrue(StringUtils.startsWith(null, (CharSequence) null), "Should return true");
        Assertions.assertFalse(StringUtils.startsWith(null, StringUtils.EMPTY), "Should return false");
        Assertions.assertTrue(StringUtils.startsWith(StringUtils.EMPTY, StringUtils.EMPTY), "Should return true");
        Assertions.assertTrue(StringUtils.startsWith("some", "some"), "Should return true");
        Assertions.assertFalse(StringUtils.startsWith("some", "Some"), "Should return false");
        Assertions.assertTrue(StringUtils.startsWithAny("something", "some"), "Should return false");
        Assertions.assertFalse(StringUtils.startsWithAny("something", "thing"), "Should return true");
        Assertions.assertTrue(StringUtils.startsWithAny("something", "thing", "so"), "Should return true");
    }
    @Test
    public void testStartsWithIgnoreCase(){
        Assertions.assertTrue(StringUtils.startsWithIgnoreCase(null, (CharSequence) null), "Should return true");
        Assertions.assertFalse(StringUtils.startsWithIgnoreCase(null, StringUtils.EMPTY), "Should return false");
        Assertions.assertTrue(StringUtils.startsWithIgnoreCase(StringUtils.EMPTY, StringUtils.EMPTY), "Should return true");
        Assertions.assertTrue(StringUtils.startsWithIgnoreCase("some", "some"), "Should return true");
        Assertions.assertTrue(StringUtils.startsWithIgnoreCase("some", "Some"), "Should return false");
        Assertions.assertTrue(StringUtils.startsWithIgnoreCase("something", "some"), "Should return false");
        Assertions.assertFalse(StringUtils.startsWithIgnoreCase("something", "thing"), "Should return true");
    }


}
