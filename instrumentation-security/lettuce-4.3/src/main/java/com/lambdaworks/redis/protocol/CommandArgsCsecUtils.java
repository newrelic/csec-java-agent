package com.lambdaworks.redis.protocol;

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

    public static Object getArgument(Object arg) {
        if (arg instanceof CommandArgs.BytesArgument){
            return getByteArgumentVal((CommandArgs.BytesArgument) arg);
        } else if (arg instanceof CommandArgs.IntegerArgument) {
            return getIntegerArgument((CommandArgs.IntegerArgument) arg);
        } else if (arg instanceof CommandArgs.DoubleArgument) {
            return getDoubleArgument((CommandArgs.DoubleArgument) arg);
        } else if (arg instanceof CommandArgs.StringArgument) {
            return getStringArgument((CommandArgs.StringArgument) arg);
        } else if (arg instanceof CommandArgs.CharArrayArgument) {
            return getCharArrayArgument((CommandArgs.CharArrayArgument) arg);
        } else if (arg instanceof CommandArgs.KeyArgument) {
            return getKeyArgument((CommandArgs.KeyArgument) arg);
        } else if (arg instanceof CommandArgs.ValueArgument) {
            return getValueArgument((CommandArgs.ValueArgument) arg);
        }
        return null;
    }
}
