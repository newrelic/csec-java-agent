#
# **New Relic Security Agent for Java**

**Repo:** [https://github.com/newrelic/csec-java-agent](https://github.com/newrelic/csec-java-agent)

**Artifact Name:** newrelic-security-agent.jar

The IAST capability should only be used in pre-production environments and never in production.

The New Relic Security Agent enables instrumentation of a Java application for Interactive Application Security Testing(IAST) and exposes exploitable vulnerabilities.

## **Installation**

This project is built and published as a dependency for use in [newrelic-java-agent](https://github.com/newrelic/newrelic-java-agent) only. Hence this can not be used directly. Typically, most users use the version auto-installed by the APM agent. You can see agent install instructions [here](https://docs.newrelic.com/docs/iast/install/).

## **Supported Java Versions**
- Java version 8 and above

## **Support Matrix**

### Frameworks and libraries

The agent automatically instruments the following frameworks.

- JAX-RS 1.0 to latest
- Spring Boot 1.4 to latest
- Struts 2.0.5 to latest
- Log4j from 2.0 to 2.20.0
- Servlet from 2.4 to latest
- Spring from 0 to latest
- Sun Net HTTP Server
- Glassfish 3.0 to latest
- Resin 3.1.9 to 4.0.x
- Jetty 9.3.0.M1 to latest
- Mule ESB 3.6 to 3.9.x
- gRPC 1.4.0 to latest [**](#grpc-instrumentation)
- Jersey 2.0 to latest
- Akka Server 10.0 to latest (with scala 2.11 and above)
- Spray Can 1.3.1 to latest (with scala 2.11 and above)
- Akka HTTP Server 10.0 to latest (with scala 2.11 and above)
- Spray HTTP 1.3.1 to latest (with scala 2.11 and above)
- Netty Server 4.0.0.Final to latest
- Netty Reactor Server 0.7.0.RELEASE to latest
- Vertx web 3.2.0 to latest
- GraphQL 16.0.0 to latest [**](#graphql-instrumentation)

#### gRPC Instrumentation
IAST for **gRPC** requires the dependency [protobuf-java-util](https://mvnrepository.com/artifact/com.google.protobuf/protobuf-java-util) for IAST request replay.

#### GraphQL Instrumentation
By default, GraphQL instrumentation is disabled in IAST as it is an experimental feature. To take advantage of this feature enable GraphQL instrumentation, update your configuration by adding the following settings under the class_transformer section:
```yaml
class_transformer:
  com.newrelic.instrumentation.security.graphql-java-16.2:
    enabled: true
```

### Java Native Operations

- File Operations 0 to latest
- JNDI operations 0 to latest
- Low Priority Instrumentation

### HTTP and messaging

The agent automatically instruments the following HTTP clients and messaging services.

- HttpURLConnection (java.net)
- XPATH from 0 to latest
- Urlconnection from 0 to latest
- Apache Httpclient from 3.0 to latest
- LDAP from to latest
- LDAPtive from 0 to latest
- Apache LDAP from 1.0.0 to latest
- Unbounded LDAP from 3.0.0 to latest
- OKHttp from 3.0.0 to latest
- JSInjection from 1.7.7.1 to latest
- GraalVM JSInjection from 19.0.0 to latest
- Rihno JSInjection from 1.7.7.1 to latest
- Camel XPATH from 3.0.0 to latest
- Jaxen XPATH from 1.1 to latest
- Saxpath 1.0
- Xalan XPATH 2.1.0 to latest
- Async Http Client from 2.0 to latest
- Ning Async HTTP Client 1.0.0 to latest
- Akka Client 10.0 to latest (with scala 2.11 and above)
- Spray Can Client 1.3.1 to latest (with scala 2.11 and above)
- Spring WebClient 5.0.0.RELEASE to latest
- Vertx Core 3.3.0 to latest

### Datastores

- Generic JDBC (any JDBC compliant driver)
- Merlia from 7.03 to latest
- Generic R2DBC from 0 to latest
- Oranxo from 3.06 to latest
- PostgreSQL from 8.0-312.jdbc3 to latest
- MariaDB R2DBC from 1.0.0 to latest
- jTDS from 1.2 to latest
- MariaDB Java Client from 1.1.7 to 3.0.0-alpha
- H2 from 1.0.57 to latest
- H2 R2DBC from 0 to latest
- Sybase from 6 to latest
- HSQLDB from 1.7.2.2 to latest
- Generic JDBC from 0 to latest
- Embedded Derby from 10.2.1.6 to latest
- MSSQL R2DBC from 0 to latest
- MySQL from 3.0.8 to latest
- Oracle JDBC from 5 to latest
- MySQL R2DBC from 0.8.2 to latest
- MongoDB from 3.0.0 to latest
- IBM DB2 from 9.1 to latest
- PostgreSQL R2DBC from 0.9.0 to latest
- Oracle R2DBC from 0.0.0 to 1.1.2
- SQLServer from jdk6 to latest
- DynamoDB-1.11.80 to latest 
- DyanamoDB-2.1.0 to latest
- Anorm from 2.0 to 2.5

## **Supported Vulnerabilities**
* Remote Code Execution
* SQL Injection
* NoSQL Injection
* Stored XSS
* Reflected XSS
* Reverse Shell attack
* File Access
* SSRF
* Application Integrity Violation
* LDAP Injection
* XPath Injection
* Weak Cryptographic Algorithm
* Weak Hash Algorithm
* Insecure Randomness
* Trust Boundary Violation
* Secure Cookie
* XQuery Injection
* JavaScript Code Injection
* Unsafe Deserialization
* Unsafe Reflection

## **Building**

#### **JDK requirements**

The Java agent uses a variety of JDK versions when building and running tests. These need to be installed and configured for your environment.

Edit or create the ~/.gradle/gradle.properties file and add the following JDKs, ensuring that the vendors/versions match what is installed in your environment (Mac OS X examples shown).

JDK 8 is required to build the agent:

`jdk8=/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home`

Additionally, the -PtestN Gradle property can be used to run tests on a specific JDK version which may require further JDK configuration. To keep test times reasonable the project only allows testing against supported LTS Java releases as well as the latest non-LTS release of Java. For example to run tests with Java 17, the -Ptest17 Gradle property would cause the test to use jdk17 as configured below:

`jdk17=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home`



### **Gradle build**

To build the agent dependency jar, run the following series of commands

From APM Java agent root directory :

```./gradlew clean :newrelic-api:publishToMavenLocal :agent-bridge:publishToMavenLocal :agent-bridge-datastore:publishToMavenLocal :newrelic-weaver-api:publishToMavenLocal :newrelic-weaver:publishToMavenLocal :newrelic-weaver-scala:publishToMavenLocal :newrelic-weaver-scala-api:publishToMavenLocal --parallel```

From CSEC java agent root dir :

```./gradlew clean :newrelic-security-api:publishToMavenLocal```

```./gradlew clean jar --parallel```

Final artifacts should be present at \<csec project root directory\>/newrelic-security-agent/build/libs

To publish csec agent on maven local use below command :

```./gradlew clean publishToMavenLocal```

## **Contributing Feedback**

Any feedback provided to New Relic about the New Relic csec-java-agent, including feedback provided as source code, comments, or other copyrightable or patentable material, is provided to New Relic under the terms of the New Relic Software License version, 1.0. If you do not provide attribution information or a copy of the license with your feedback, you waive the performance of those requirements of the New Relic Software License with respect to New Relic. The license grant regarding any feedback is irrevocable.

Keep in mind that when you submit a pull request or other feedback, you'll need to sign the CLA via the click-through using CLA-Assistant. You only have to sign the CLA one time per project.
If you have any questions drop us an email at opensource@newrelic.com.

**A note about vulnerabilities**

As noted in our [security policy](https://github.com/newrelic/csec-java-agent/security/policy), New Relic is committed to the privacy and security of our customers and their data. We believe that providing coordinated disclosure by security researchers and engaging with the security community are important means to achieve our security goals.

If you believe you have found a security vulnerability in this project or any of New Relic's products or websites, we welcome and greatly appreciate you reporting it to New Relic through [HackerOne](https://hackerone.com/newrelic).

If you would like to contribute to this project, review [these guidelines](https://github.com/newrelic/csec-java-agent/blob/main/CONTRIBUTING.md).

## **License**

New Relic Security Agent for Java is licensed under the New Relic Software License v. 1.0

The New Relic Security Agent for Java also uses source code from third-party libraries. You can find full details on which libraries are used and the terms under which they are licensed in the third-party notices document.
