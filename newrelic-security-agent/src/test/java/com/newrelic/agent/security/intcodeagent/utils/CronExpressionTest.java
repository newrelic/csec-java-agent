package com.newrelic.agent.security.intcodeagent.utils;

import org.junit.Assert;
import org.junit.Test;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.TimeZone;

public class CronExpressionTest {

    @Test
    public void parseExceptionTest() throws ParseException {
        Assert.assertFalse(CronExpression.isValidExpression(" "));
        Assert.assertFalse(CronExpression.isValidExpression("*****"));
        Assert.assertFalse(CronExpression.isValidExpression("* * * * * *"));
        Assert.assertTrue(CronExpression.isValidExpression("* * * ? * *"));
    }

    @Test(expected = ParseException.class)
    public void parseException1Test() throws ParseException {
        new CronExpression("");
    }

    @Test(expected = ParseException.class)
    public void parseException2Test() throws ParseException {
        new CronExpression(" ");
    }

    @Test(expected = ParseException.class)
    public void parseException3Test() throws ParseException {
        new CronExpression("*****");
    }

    @Test(expected = ParseException.class)
    public void parseException4Test() throws ParseException {
        new CronExpression("* * * * * *");
    }

    @Test(expected = ParseException.class)
    public void parseException5Test() throws ParseException {
        CronExpression.validateExpression(" ");
    }

    @Test(expected = ParseException.class)
    public void parseException6Test() throws ParseException {
        CronExpression.validateExpression("*****");
    }

    @Test(expected = ParseException.class)
    public void parseException7Test() throws ParseException {
        CronExpression.validateExpression("* * * * * *");
    }

    @Test(expected = ParseException.class)
    public void parseException8Test() throws ParseException {
        CronExpression.validateExpression("* * ? * * *");
    }

    @Test
    public void parseException9Test() throws ParseException {
        CronExpression.validateExpression("* * * ? * *");
    }

    @Test
    public void isSatisfiedByTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");

        expression.setTimeZone(TimeZone.getDefault());
        expression.setTimeZone(null);

        Assert.assertEquals(TimeZone.getDefault(), expression.getTimeZone());

        System.out.println(expression.getExpressionSummary());
        Assert.assertEquals("* * * ? * *", expression.toString());
        Assert.assertEquals("* * * ? * *", expression.getCronExpression());
        Assert.assertTrue(expression.isSatisfiedBy(Date.from(Instant.EPOCH)));
        Assert.assertTrue(expression.isSatisfiedBy(Date.from(Instant.now())));
        Assert.assertTrue(expression.isSatisfiedBy(Date.from(Instant.ofEpochMilli(1000))));
        Assert.assertNull(expression.getFinalFireTime());
        Assert.assertNull(expression.getTimeBefore(Date.from(Instant.EPOCH)));
    }

    @Test
    public void getLastDayOfMonthTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        Assert.assertEquals(31, expression.getLastDayOfMonth(1, 2000));
        Assert.assertEquals(31, expression.getLastDayOfMonth(3, 2000));
        Assert.assertEquals(31, expression.getLastDayOfMonth(5, 2000));
        Assert.assertEquals(31, expression.getLastDayOfMonth(7, 2000));
        Assert.assertEquals(31, expression.getLastDayOfMonth(8, 2000));
        Assert.assertEquals(31, expression.getLastDayOfMonth(10, 2000));
        Assert.assertEquals(31, expression.getLastDayOfMonth(12, 2000));
        Assert.assertEquals(30, expression.getLastDayOfMonth(4, 2000));
        Assert.assertEquals(30, expression.getLastDayOfMonth(6, 2000));
        Assert.assertEquals(30, expression.getLastDayOfMonth(9, 2000));
        Assert.assertEquals(30, expression.getLastDayOfMonth(11, 2000));
        Assert.assertEquals(29, expression.getLastDayOfMonth(2, 2000));
        Assert.assertEquals(28, expression.getLastDayOfMonth(2, 2001));
    }

    @Test(expected = IllegalArgumentException.class)
    public void getLastDayOfMonthExceptionTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        Assert.assertEquals(31, expression.getLastDayOfMonth(13, 2000));
    }

    @Test
    public void getDayOfWeekNumberTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        Assert.assertEquals(1, expression.getDayOfWeekNumber("SUN"));
        Assert.assertEquals(-1, expression.getDayOfWeekNumber("XYZ"));
    }

    @Test
    public void getMonthNumberTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        Assert.assertEquals(0, expression.getMonthNumber("JAN"));
        Assert.assertEquals(-1, expression.getMonthNumber("XYZ"));
    }

    @Test
    public void getExpressionSetSummaryTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        Assert.assertEquals("1", expression.getExpressionSetSummary(Collections.singleton(1)));
        Assert.assertEquals("?", expression.getExpressionSetSummary(Collections.singleton(CronExpression.NO_SPEC)));
        Assert.assertEquals("*", expression.getExpressionSetSummary(Collections.singleton(CronExpression.ALL_SPEC)));
    }

    @Test
    public void getExpressionSetSummary1Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        ArrayList<Integer> list = new ArrayList<>();
        list.add(1);
        Assert.assertEquals("1", expression.getExpressionSetSummary(list));

        list.clear();
        list.add(CronExpression.NO_SPEC);
        Assert.assertEquals("?", expression.getExpressionSetSummary(list));

        list.clear();
        list.add(CronExpression.ALL_SPEC);
        Assert.assertEquals("*", expression.getExpressionSetSummary(Collections.singleton(CronExpression.ALL_SPEC)));
    }

    @Test(expected = NumberFormatException.class)
    public void getNumericValueTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        Assert.assertEquals(1, expression.getNumericValue("1 2", 1));
    }

    @Test
    public void getNumericValue1Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        Assert.assertEquals(1, expression.getNumericValue("1", 0));
    }

    @Test
    public void getValue1Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");

        Assert.assertEquals(1, expression.getValue(1, "JAN", 1).pos);
        Assert.assertEquals(1, expression.getValue(1, "JAN", 1).value);

        Assert.assertEquals(1, expression.getValue(1, "1 2 3", 1).pos);
        Assert.assertEquals(1, expression.getValue(1, "1 2 3", 1).value);

    }

    @Test
    public void storeExpressionValsSecondTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        Assert.assertEquals(1, expression.storeExpressionVals(0, "* * * ? * *", 0));
        Assert.assertEquals(2, expression.storeExpressionVals(0, "0 12 * * ?", 0));
        Assert.assertEquals(3, expression.storeExpressionVals(0, "0-5 13 * * ?", 0));
        Assert.assertEquals(3, expression.storeExpressionVals(0, "JAN", CronExpression.MONTH));
        Assert.assertEquals(7, expression.storeExpressionVals(0, "JAN-FEB", CronExpression.MONTH));
        Assert.assertEquals(7, expression.storeExpressionVals(0, "SUN-MON", CronExpression.DAY_OF_WEEK));
        Assert.assertEquals(3, expression.storeExpressionVals(0, "SUN", CronExpression.DAY_OF_WEEK));

        Assert.assertEquals(7, expression.storeExpressionVals(0, "MON#1", CronExpression.DAY_OF_WEEK));
        Assert.assertEquals(1, expression.storeExpressionVals(0, "L", CronExpression.DAY_OF_WEEK));
        Assert.assertEquals(1, expression.storeExpressionVals(0, "L", CronExpression.DAY_OF_MONTH));
        Assert.assertEquals(4, expression.storeExpressionVals(0, "L-1", CronExpression.DAY_OF_MONTH));
        Assert.assertEquals(2, expression.storeExpressionVals(0, "LW", CronExpression.DAY_OF_MONTH));
        Assert.assertEquals(3, expression.storeExpressionVals(0, "1/4", CronExpression.DAY_OF_WEEK));
    }

    @Test(expected = ParseException.class)
    public void storeExpressionValsHourTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "0/4", CronExpression.DAY_OF_WEEK);
    }

    @Test(expected = ParseException.class)
    public void storeExpressionMonthTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "1/13", CronExpression.MONTH);
    }

    @Test(expected = ParseException.class)
    public void storeExpressionHourTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "1/25", CronExpression.HOUR);
    }

    @Test(expected = ParseException.class)
    public void storeExpressionDayOfMonthTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "1/32", CronExpression.DAY_OF_MONTH);
    }

    @Test(expected = ParseException.class)
    public void storeExpressionMinuteTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "1/61", CronExpression.MINUTE);
    }

    @Test(expected = ParseException.class)
    public void storeExpressionValsWeekDays1Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "1/45", CronExpression.DAY_OF_WEEK);
    }

    @Test(expected = ParseException.class)
    public void weekStoreExpressionValsExceptionTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "FEB", CronExpression.DAY_OF_WEEK);
    }

    @Test(expected = ParseException.class)
    public void monthStoreExpressionValsExceptionTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "SUN", CronExpression.MONTH);
    }

    @Test(expected = ParseException.class)
    public void monthStoreExpressionValsException1Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "FEB-MON", CronExpression.MONTH);
    }

    @Test(expected = ParseException.class)
    public void dayOfWeekStoreExpressionValsException1Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "8", CronExpression.DAY_OF_WEEK);
    }

    @Test(expected = ParseException.class)
    public void dayOfWeekStoreExpressionValsException2Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "SUN#9", CronExpression.DAY_OF_WEEK);
    }

    @Test(expected = ParseException.class)
    public void dayOfMonthStoreExpressionValsException1Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "8", CronExpression.DAY_OF_WEEK);
    }

    @Test(expected = ParseException.class)
    public void dayOfMonthStoreExpressionValsException2Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.storeExpressionVals(0, "L-41", CronExpression.DAY_OF_MONTH);
    }

    @Test
    public void checkNowTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        Assert.assertEquals(1, expression.checkNext(0, "* * * ? * *",1, 0));
        Assert.assertEquals(1, expression.checkNext(0, "0 12 * * ?", 1,0));
        Assert.assertEquals(1, expression.checkNext(0, "0-5 13 * * ?", 1,0));
        Assert.assertEquals(1, expression.checkNext(0, "JAN", 1, CronExpression.MONTH));
        Assert.assertEquals(1, expression.checkNext(0, "JAN-FEB", 1, CronExpression.MONTH));
        Assert.assertEquals(1, expression.checkNext(0, "SUN-MON", 1, CronExpression.DAY_OF_WEEK));
        Assert.assertEquals(2, expression.checkNext(0, "-2", 1, CronExpression.DAY_OF_WEEK));
        Assert.assertEquals(4, expression.checkNext(0, "-23", 1, CronExpression.DAY_OF_MONTH));
        Assert.assertEquals(4, expression.checkNext(0, "-2/4", 1, CronExpression.DAY_OF_MONTH));
        Assert.assertEquals(6, expression.checkNext(0, "-2/20", 1, CronExpression.DAY_OF_MONTH));
        Assert.assertEquals(2, expression.checkNext(0, "#1", 1, CronExpression.DAY_OF_WEEK));
        Assert.assertEquals(1, expression.checkNext(0, "L", 1, CronExpression.DAY_OF_WEEK));
        Assert.assertEquals(2, expression.checkNext(0, "/4",1, CronExpression.DAY_OF_WEEK));
        Assert.assertEquals(1, expression.checkNext(0, "W",1, CronExpression.DAY_OF_MONTH));
        Assert.assertEquals(2, expression.checkNext(2, "W",1, CronExpression.DAY_OF_MONTH));
    }

    @Test(expected = ParseException.class)
    public void dayOfWeekCheckNextException1Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.checkNext(0, "#6", 1, CronExpression.DAY_OF_MONTH);
    }

    @Test(expected = ParseException.class)
    public void dayOfWeekCheckNextException3Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.checkNext(0, "W", 32, CronExpression.DAY_OF_MONTH);
    }

    @Test(expected = ParseException.class)
    public void dayOfWeekCheckNextException2Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.checkNext(0, "#6", 1, CronExpression.DAY_OF_WEEK);
    }

    @Test(expected = ParseException.class)
    public void monthCheckNextException1Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.checkNext(0, "W", 1, CronExpression.DAY_OF_WEEK);
    }

    @Test(expected = ParseException.class)
    public void monthCheckNextException2Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.checkNext(0, "W", 32, CronExpression.DAY_OF_WEEK);
    }

    @Test(expected = ParseException.class)
    public void CheckNextException2Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        expression.checkNext(0, "/", 1, CronExpression.DAY_OF_WEEK);
    }

    @Test
    public void setCalendarHourTest() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        Calendar cal = Calendar.getInstance();
        expression.setCalendarHour(cal, 1);
        Assert.assertEquals(1, cal.get(Calendar.HOUR_OF_DAY));
    }

    @Test
    public void setCalendarHour1Test() throws ParseException {
        CronExpression expression = new CronExpression("* * * ? * *");
        Calendar cal = Calendar.getInstance();
        expression.setCalendarHour(cal, 25);
        Assert.assertEquals(2, cal.get(Calendar.HOUR_OF_DAY));
    }
}
