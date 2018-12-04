# K2-JavaAgent

This module is an extension of instrumentation module that defines an interceptor (LoggingInterceptor) aimed at logging executions of third-party code.

## Output
For each execution of an instrumented method, the agent generates an event with the following informations
pid = process id of JVM
startTime = Method execution start time
source = Instrumented method
currentMethod = Execution method
userMethodName = Name of the parent execution method 
userClassName = Full name of the user's class 
lineNumber = currentMethod line number
parameters = JSON Serialization (if possible) of the method arguments/exceptions
eventGenerationTime = Event generation time


## Prerequisites
- Make sure you have Maven version 3 or above and Java version 8 installed.
- Also, make sure your java home is set properly.  
- It is recommended to use a separate tomcat-v8 for this deployment and any instance of that tomcat should not be running.

## Clone Projects 

Following are the projects need to be cloned

https://github.com/k2io/K2-Instrumentation
```
git clone https://github.com/k2io/K2-Instrumentation.git
```

https://github.com/k2io/k2-jnr-unixsocket
```
git clone https://github.com/k2io/k2-jnr-unixsocket.git
```

https://github.com/k2io/k2-jnr-ffi
```
git clone https://github.com/k2io/k2-jnr-ffi.git
```

https://github.com/k2io/k2-asm
```
git clone https://github.com/k2io/k2-asm.git
```

https://github.com/k2io/k2-json-simple
```
git clone https://github.com/k2io/k2-json-simple.git
```

https://github.com/k2io/K2-JavaAgent
```
git clone https://github.com/k2io/K2-JavaAgent
```

## Build
Build Sequence is important, follow the below sequence.

go to directory to k2-asm, use below command to make the build of k2-asm
```
cd k2-asm
mvn clean install
```

go to directory to k2-jnr-ffi, use below command to make the build of jnr-ffi
```
cd k2-jnr-ffi
mvn clean install
```

go to directory to k2-jnr-unixsocket, use below command to make the build of jnr-unixsocket
```
cd k2-jnr-unixsocket
mvn clean install
```

go to directory to k2-json-simple, use below command to make the build of json-simple
```
cd k2-json-simple
mvn clean install
```

go to directory to K2-Instrumentation, use below command
```
cd K2-Instrumentation
```

use below maven command to make the build of K2-Instrumentation
```
mvn clean install
```

go to directory to K2-JavaAgent, use below command
```
cd K2-JavaAgent
```

use below maven command to make the build of K2-JavaAgent
```
mvn clean install
```

## Run
Copy the logging-instrumentation-1.0.0-SNAPSHOT-jar-with-dependencies.jar to your worksapce 
Add the following jvm arguments for tomcat or jetty to instrument
```
-noverify
-javaagent:<path-to-logging-instrumentation-1.0.0-SNAPSHOT-jar-with-dependencies.jar>
-Xbootclasspath/a:<path-to-logging-instrumentation-1.0.0-SNAPSHOT-jar-with-dependencies.jar>
```

-Note: Make sure int-code agent is running before you start the server

