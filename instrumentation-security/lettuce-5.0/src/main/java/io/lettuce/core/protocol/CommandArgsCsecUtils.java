package io.lettuce.core.protocol;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;

import java.util.List;

public class CommandArgsCsecUtils {

    public static List<CommandArgs.SingularArgument> getSingularArgs(CommandArgs_Instrumentation commandArgs) {
        return commandArgs.singularArguments;
    }

    public static byte[] getByteArgumentVal(CommandArgs.BytesArgument bytesArgument) {
        return bytesArgument.val;
    }

    public static long getIntegerArgument(CommandArgs.IntegerArgument integerArgument) {
        return integerArgument.val;
    }

    public static double getDoubleArgument(CommandArgs.DoubleArgument doubleArgument) {
        return doubleArgument.val;
    }

    public static String getStringArgument(CommandArgs.StringArgument stringArgument) {
        return stringArgument.val;
    }

    public static char[] getCharArrayArgument(CommandArgs.CharArrayArgument charArrayArgument) {
        return charArrayArgument.val;
    }

    public static Object getKeyArgument(CommandArgs.KeyArgument keyArgument) {
        return keyArgument.key;
    }

    public static Object getValueArgument(CommandArgs.ValueArgument valueArgument) {
        return valueArgument.val;
    }

    public static Object getSpringDataArgument(Object argument){
        Object returnValue = null;
        try {
            System.out.println("Get Arguments call for obj "+ argument.hashCode() +":"+argument );
            returnValue = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GenericHelper.NR_SEC_CUSTOM_SPRING_REDIS_ATTR + argument.hashCode(), Object.class);
        } catch (Exception e){
            returnValue = argument;
        }
        return (returnValue!=null)?returnValue:argument;
    }

    public static Object getArgument(Object arg) {
        Object argument = null;
        if (arg instanceof CommandArgs.BytesArgument){
            argument = getByteArgumentVal((CommandArgs.BytesArgument) arg);
        } else if (arg instanceof CommandArgs.IntegerArgument) {
            argument = getIntegerArgument((CommandArgs.IntegerArgument) arg);
        } else if (arg instanceof CommandArgs.DoubleArgument) {
            argument = getDoubleArgument((CommandArgs.DoubleArgument) arg);
        } else if (arg instanceof CommandArgs.StringArgument) {
            argument = getStringArgument((CommandArgs.StringArgument) arg);
        } else if (arg instanceof CommandArgs.CharArrayArgument) {
            argument = getCharArrayArgument((CommandArgs.CharArrayArgument) arg);
        } else if (arg instanceof CommandArgs.KeyArgument) {
            argument = getKeyArgument((CommandArgs.KeyArgument) arg);
        } else if (arg instanceof CommandArgs.ValueArgument) {
            argument = getValueArgument((CommandArgs.ValueArgument) arg);
        }
        if(argument != null) {
            return getSpringDataArgument(argument);
        } else {
            return null;
        }
    }
}
