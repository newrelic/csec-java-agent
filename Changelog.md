# Changelog
Noteworthy changes to the agent are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.1] - TBD
### Adds
- [PR-296](https://github.com/newrelic/csec-java-agent/pull/296) Apache Solr Support: The security agent now also supports Apache Solr Version 4.0.0 and above. [NR-288599](https://new-relic.atlassian.net/browse/NR-288599)
- [PR-275](https://github.com/newrelic/csec-java-agent/pull/275) The maximum permissible size for a request body for scan will be set at 500KB. [NR-174195](https://new-relic.atlassian.net/browse/NR-174195)
- [PR-306](https://github.com/newrelic/csec-java-agent/pull/306) Add csec prefix to all instrumentation Jar, this resolves CVE flagged by third party scanners on our instrumentation JARs. [NR-289249](https://new-relic.atlassian.net/browse/NR-289249)
- [PR-303](https://github.com/newrelic/csec-java-agent/pull/303) Honour OFF Flag, Handle Boolean values for config log_level. [NR-293102](https://new-relic.atlassian.net/browse/NR-293102)
- [PR-299](https://github.com/newrelic/csec-java-agent/pull/299) Support Authentication capabilities for Proxy Settings. [NR-283945](https://new-relic.atlassian.net/browse/NR-283945)
- [PR-313](https://github.com/newrelic/csec-java-agent/pull/313) Processing of the security agent will persist even if the creation of the security home directory encounters an issue. [NR-297206](https://new-relic.atlassian.net/browse/NR-297206)
- [PR-277](https://github.com/newrelic/csec-java-agent/pull/277) Improve Management of Log file size and its count. [NR-272900](https://new-relic.atlassian.net/browse/NR-272900)
- [PR-314](https://github.com/newrelic/csec-java-agent/pull/314) Report error to Error Inbox upon connection failure to Security Engine. [NR-299700](https://new-relic.atlassian.net/browse/NR-299700)
- [PR-316](https://github.com/newrelic/csec-java-agent/pull/316) Detailed IAST Scan metric reporting via HealthCheck. [NR-267166](https://new-relic.atlassian.net/browse/NR-267166)
- [PR-302](https://github.com/newrelic/csec-java-agent/pull/302) Detect API Endpoint of the Application for Vertx Framework. [NR-287771](https://new-relic.atlassian.net/browse/NR-287771)
- [PR-293](https://github.com/newrelic/csec-java-agent/pull/293), [PR-284](https://github.com/newrelic/csec-java-agent/pull/284), [PR-302](https://github.com/newrelic/csec-java-agent/pull/302) Detect route of an incoming request for mule server, play framework and Vertx Framework. [NR-283915](https://new-relic.atlassian.net/browse/NR-283915), [NR-265915](https://new-relic.atlassian.net/browse/NR-265915), [NR-287771](https://new-relic.atlassian.net/browse/NR-287771)

### Changes
- [PR-265](https://github.com/newrelic/csec-java-agent/pull/265) Improve Secure Cookie event reporting to provide detailed vulnerability. [NR-273609](https://new-relic.atlassian.net/browse/NR-273609)
- [PR-283](https://github.com/newrelic/csec-java-agent/pull/283) Update IAST Header Parsing Minimum Expected Length Set to 8. [NR-282647](https://new-relic.atlassian.net/browse/NR-282647)
- [PR-308](https://github.com/newrelic/csec-java-agent/pull/308) Remove jackson-dataformat-properties to address [CVE-2023-3894](https://www.cve.org/CVERecord?id=CVE-2023-3894) and exclude transitive dependency junit to address [CVE-2020-15250](https://www.cve.org/CVERecord?id=CVE-2020-15250) [NR-295033](https://new-relic.atlassian.net/browse/NR-295033)

### Fixes
- [PR-292](https://github.com/newrelic/csec-java-agent/pull/292) Fix for ClassNotFoundException observed in glassfish server [NR-262453](https://new-relic.atlassian.net/browse/NR-262453)
- [PR-286](https://github.com/newrelic/csec-java-agent/pull/286) Detect correct user class in Netty Reactor Server [NR-253551](https://new-relic.atlassian.net/browse/NR-253551)
- [PR-317](https://github.com/newrelic/csec-java-agent/pull/317) Add a workaround for an issue where New Relic Security Agent breaks the gRPC endpoints [#130](https://github.com/newrelic/csec-java-agent/issues/310). [NR-299709](https://new-relic.atlassian.net/browse/NR-299709)

### Deprecations
- Status File Used for Debugging: This feature has been deprecated. All debugging capabilities have been moved to either Init Logging or [Error Inbox](https://docs.newrelic.com/docs/errors-inbox/errors-inbox/) and will be removed in a future agent release. [NR-293966](https://new-relic.atlassian.net/browse/NR-293966)

## [1.4.0] - 2024-6-24
### Changes
- Json Version bump to 1.2.3 due to [NR-254157](https://new-relic.atlassian.net/browse/NR-254157) implementation.
- [PR-260](https://github.com/newrelic/csec-java-agent/pull/260) SpyMemcached Support : The security agent now also supports SpyMemcached Version 2.12.0 and above. [NR-171576](https://new-relic.atlassian.net/browse/NR-171576)
- [PR-241](https://github.com/newrelic/csec-java-agent/pull/241) Vertx-Web Support : The security agent now also supports Vertx-Web Version 3.2.0 and above. [NR-254180](https://new-relic.atlassian.net/browse/NR-254180), [NR-254181](https://new-relic.atlassian.net/browse/NR-254181), [NR-254182](https://new-relic.atlassian.net/browse/NR-254182) 
- [PR-245](https://github.com/newrelic/csec-java-agent/pull/245) Vert.x-Core Support : The security agent now also supports Vert.x-Core Version 3.3.0 and above. [NR-254146](https://new-relic.atlassian.net/browse/NR-254146), [NR-254156](https://new-relic.atlassian.net/browse/NR-254156) 
- [PR-254](https://github.com/newrelic/csec-java-agent/pull/254) API Endpoint detection support for Netty Reactor Server. [NR-267158](https://new-relic.atlassian.net/browse/NR-267158)
- [PR-269](https://github.com/newrelic/csec-java-agent/pull/269), [PR-261](https://github.com/newrelic/csec-java-agent/pull/261) Functionality to report NPE, Uncaught exceptions And 5xx Errors. [NR-273711](https://new-relic.atlassian.net/browse/NR-273711), [NR-277763](https://new-relic.atlassian.net/browse/NR-277763)
- [PR-267](https://github.com/newrelic/csec-java-agent/pull/267) Implement Fallback mechanism for route detection of an incoming request [NR-273607](https://new-relic.atlassian.net/issues/NR-273607)
- [PR-256](https://github.com/newrelic/csec-java-agent/pull/256), [PR-259](https://github.com/newrelic/csec-java-agent/pull/259), [PR-258](https://github.com/newrelic/csec-java-agent/pull/258) Feature to detect route of an incoming request for Jax-RS and Spring Framework. [NR-265913](https://new-relic.atlassian.net/browse/NR-265913), [NR-261653](https://new-relic.atlassian.net/browse/NR-261653), [NR-273605](https://new-relic.atlassian.net/browse/NR-273605)
- [PR-126](https://github.com/newrelic/csec-java-agent/pull/126), [PR-127](https://github.com/newrelic/csec-java-agent/pull/127), [PR-128](https://github.com/newrelic/csec-java-agent/pull/128), [PR-129](https://github.com/newrelic/csec-java-agent/pull/129) Jedis Support : The security agent now also supports Jedis Version 1.4.0 and above. [NR-174176](https://new-relic.atlassian.net/browse/NR-174176)
- [PR-287](https://github.com/newrelic/csec-java-agent/pull/287) Support for Proxy Settings for Connecting to the Security Engine, with known limitation of missing Authentication capabilities.

### Fixes
- [PR-255](https://github.com/newrelic/csec-java-agent/pull/255) Handle InvalidPathException thrown by Paths.get method [NR-262452](https://new-relic.atlassian.net/browse/NR-262452)
- [PR-216](https://github.com/newrelic/csec-java-agent/pull/216) Extract Server Configuration to resolve IAST localhost connection with application for Glassfish Server. [NR-223808](https://new-relic.atlassian.net/browse/NR-223808)
- [PR-214](https://github.com/newrelic/csec-java-agent/pull/214) Extract Server Configuration to resolve IAST localhost connection with application for Weblogic Server. [NR-223809](https://new-relic.atlassian.net/browse/NR-223809)
- [PR-242](https://github.com/newrelic/csec-java-agent/pull/242) Fix for User Class detection in Play Framework [NR-264101](https://new-relic.atlassian.net/browse/NR-264101)
- [PR-268](https://github.com/newrelic/csec-java-agent/pull/268) Fix for Play Framework Application Crash. [NR-273623](https://new-relic.atlassian.net/browse/NR-273623)
- [PR-271](https://github.com/newrelic/csec-java-agent/pull/271) Remove hard dependency of Newrelic API. [NR-278213](https://new-relic.atlassian.net/browse/NR-278213)
- [PR-272](https://github.com/newrelic/csec-java-agent/pull/272) Fix for missing File Vulnerability as Event was not generated by CSEC Java Agent. [NR-278211](https://new-relic.atlassian.net/browse/NR-278211)

## [1.3.0] - 2024-5-16
### Changes
- [PR-186](https://github.com/newrelic/csec-java-agent/pull/186) Feature to detect API Endpoint of the Application [NR-222163](https://new-relic.atlassian.net/browse/NR-222163)
- [PR-132](https://github.com/newrelic/csec-java-agent/pull/132) JCache Support : The security agent now also supports jCache 1.0.0 and above [NR-175383](https://new-relic.atlassian.net/browse/NR-175383)
- [PR-193](https://github.com/newrelic/csec-java-agent/pull/193) Spray HTTP Server Support : The security agent now also supports Spray HTTP Server version 1.3.1 and above (with scala 2.11 and above) [NR-230246](https://new-relic.atlassian.net/browse/NR-230246), [NR-230248](https://new-relic.atlassian.net/browse/NR-230248)
- [PR-195](https://github.com/newrelic/csec-java-agent/pull/195) Spray Can Server Support : The security agent now also supports Spray Can Server version 1.3.1 and above (with scala 2.11 and above) [NR-230246](https://new-relic.atlassian.net/browse/NR-230246), [NR-230248](https://new-relic.atlassian.net/browse/NR-230248)
- [PR-194](https://github.com/newrelic/csec-java-agent/pull/194) Spray Client Support : The security agent now also supports Spray Client version 1.3.1 and above (with scala 2.11 and above) [NR-230243](https://new-relic.atlassian.net/browse/NR-230243), [NR-230245](https://new-relic.atlassian.net/browse/NR-230245)
- [PR-202](https://github.com/newrelic/csec-java-agent/pull/202) Netty Server support : The security agent now also supports Netty Server version 4.0.0.Final and above. [NR-234864](https://new-relic.atlassian.net/browse/NR-234864)
- [PR-220](https://github.com/newrelic/csec-java-agent/pull/220) Netty Reactor Server support : The security agent now also supports Netty Reactor Server version 0.7.0.RELEASE and above. [NR-249812](https://new-relic.atlassian.net/browse/NR-249812)
- [PR-239](https://github.com/newrelic/csec-java-agent/pull/239) Spring WebClient Support : The security agent now also supports Spring WebClient version 5.0.0.RELEASE and above. [NR-258894](https://new-relic.atlassian.net/browse/NR-258894), [NR-258895](https://new-relic.atlassian.net/browse/NR-258895)
- [PR-219](https://github.com/newrelic/csec-java-agent/pull/219) Enable functionality to scan NewRelic applications using `security.is_home_app` config, default value is false
- [PR-217](https://github.com/newrelic/csec-java-agent/pull/217) Revamp user class detection technique, use server level endpoints. [NR-211161](https://new-relic.atlassian.net/browse/NR-211161)
- Resin Support : The security agent now also supports resin server [NR-171577](https://new-relic.atlassian.net/browse/NR-171577)
- Anorm Support : The security agent now also supports Anorm Datastore version 2.0 to 2.5 [NR-171575](https://new-relic.atlassian.net/browse/NR-171575)

### Fixes
- [PR-202](https://github.com/newrelic/csec-java-agent/pull/202) Extract Server Configuration to resolve IAST localhost connection with application for Netty server. [NR-238324](https://new-relic.atlassian.net/browse/NR-238324)
- [PR-237](https://github.com/newrelic/csec-java-agent/pull/237) Fix for Correct User Class Detection in Sun-Net-HttpServer [NR-254564](https://new-relic.atlassian.net/browse/NR-254564)
- [PR-243](https://github.com/newrelic/csec-java-agent/pull/243) Improvement in fallback mechanism for NR_CSEC_HOME [NR-260723](https://new-relic.atlassian.net/browse/NR-260723)
- [PR-248](https://github.com/newrelic/csec-java-agent/pull/248) Fix for Regression in File Integrity Event Generation [NR-267172](https://new-relic.atlassian.net/browse/NR-267172)
- [PR-249](https://github.com/newrelic/csec-java-agent/pull/249), [PR-244](https://github.com/newrelic/csec-java-agent/pull/244) Improvements in IAST Replay [NR-267169](https://new-relic.atlassian.net/browse/NR-267169), [NR-265208](https://new-relic.atlassian.net/browse/NR-265208)
- [PR-235](https://github.com/newrelic/csec-java-agent/pull/235) Fix for NullPointerException observed in JDBC-GENERIC  [NR-232657](https://new-relic.atlassian.net/browse/NR-232657)
- [PR-226](https://github.com/newrelic/csec-java-agent/pull/226) Fix for NoClassDefFoundError observed in JAVAX-JNDI Instrumentation [NR-254566](https://new-relic.atlassian.net/browse/NR-254566)
- [PR-225](https://github.com/newrelic/csec-java-agent/pull/225) Fix for FileAlreadyExistException observed in IAST Replay [NR-254565](https://new-relic.atlassian.net/browse/NR-254565)
- [PR-222](https://github.com/newrelic/csec-java-agent/pull/222) Exclude Milestone Release for Jax-RS, due to release of version 4.0.0-M2 on 9th March 2024 [NR-256459](https://new-relic.atlassian.net/browse/NR-256459)
- [PR-232](https://github.com/newrelic/csec-java-agent/pull/232) Exclude Latest Release version 12.7.0 for mssql-jdbc released on 08th April 2024 [NR-256461](https://new-relic.atlassian.net/browse/NR-256461)
- [PR-247](https://github.com/newrelic/csec-java-agent/pull/247) Exclude Latest Release version 1.7.14 for Rhino-JS-Engine released on 29th April 2024 [NR-265206](https://new-relic.atlassian.net/browse/NR-265206)
- [PR-219](https://github.com/newrelic/csec-java-agent/pull/219) Fixed an issue where lambda functions were causing class circularity errors [NR-239192](https://new-relic.atlassian.net/browse/NR-239192)

## [1.2.1] - 2024-4-19
### Fixes
- [NR-259467](https://new-relic.atlassian.net/browse/NR-259467) Fix issue of nested event generation from CSEC's agent itself [PR-230](https://github.com/newrelic/csec-java-agent/pull/230)

### Changes
- [NR-256459](https://new-relic.atlassian.net/browse/NR-256459) Exclude JAX RS 4.0.0-M2 version from Instrumentation [PR-231](https://github.com/newrelic/csec-java-agent/pull/231)
- [NR-256461](https://new-relic.atlassian.net/browse/NR-256461) Exclude mssql-jdbc version 12.7.0 from Instrumentation [PR-232](https://github.com/newrelic/csec-java-agent/pull/232)
- [NR-260369](https://new-relic.atlassian.net/browse/NR-260369) Dependency version bump of commons-compress:1.21 to commons-compress:1.26.0 

## [1.2.0] - 2024-3-28
### Changes
- Json Version bump to 1.2.0 due to [NR-235776](https://new-relic.atlassian.net/browse/NR-235776) implementation.
- [NR-234886](https://new-relic.atlassian.net/browse/NR-234886) IAST replay header decryption due to Security Findings [PR-207](https://github.com/newrelic/csec-java-agent/pull/207)

### Fixes
- [NR-253538](https://new-relic.atlassian.net/browse/NR-253538) Fix issue related to the instrumentation of the Rhino JavaScript Engine that occurred while reading the script. [PR-211](https://github.com/newrelic/csec-java-agent/pull/211) 

## [1.1.2] - 2024-3-11
### Changes
- [NR-174177](https://new-relic.atlassian.net/browse/NR-174177) Ning Async HTTP client Support: The security agent now also supports com.ning:async-http-client 1.0.0 and above [PR-152](https://github.com/newrelic/csec-java-agent/pull/152), [PR-118](https://github.com/newrelic/csec-java-agent/pull/118), [PR-116](https://github.com/newrelic/csec-java-agent/pull/116)
- [NR-181375](https://new-relic.atlassian.net/browse/NR-181375) Jersey Support: The security agent now also supports Jersey 2.0 and above [PR-150](https://github.com/newrelic/csec-java-agent/pull/150), [PR-149](https://github.com/newrelic/csec-java-agent/pull/149) 
- [NR-187224](https://new-relic.atlassian.net/browse/NR-187224) Mule Support: The security agent now also supports Mule server version 3.6 to 3.9.x [PR-144](https://github.com/newrelic/csec-java-agent/pull/144), [PR-143](https://github.com/newrelic/csec-java-agent/pull/143)
- Jetty v12 Support: The security agent now also support Jetty version 12 and above [PR-106](https://github.com/newrelic/csec-java-agent/pull/106)
- [NR-174175](https://new-relic.atlassian.net/browse/NR-174175) Lettuce Support: The security agent now also supports Lettuce 4.4.0.Final and above [PR-125](https://github.com/newrelic/csec-java-agent/pull/125)
- [NR-234869](https://new-relic.atlassian.net/browse/NR-234869) GHA Update Unit Test Action for Testing Unit tests with different java-version with re-tries on failure [PR-204](https://github.com/newrelic/csec-java-agent/pull/204)

### Fixes
- [NR-223811](https://new-relic.atlassian.net/browse/NR-223811) Extract Server Configuration to resolve IAST localhost connection with application for wildfly server [PR-192](https://github.com/newrelic/csec-java-agent/pull/192)
- [NR-234903](https://new-relic.atlassian.net/browse/NR-234903) Trustboundary events now will have list of string as parameter schema

## [1.1.1] - 2024-2-16
### Changes
- [NR-223414](https://new-relic.atlassian.net/browse/NR-223414) Enable Low Priority Instrumentation by default [PR-179](https://github.com/newrelic/csec-java-agent/pull/179)
- [NR-219439](https://new-relic.atlassian.net/browse/NR-219439) Akka server v10.0+ Support: The security agent now supports Akka server version 10.0 and above (with scala 2.11 and above) [PR-175](https://github.com/newrelic/csec-java-agent/pull/175)

### Fixes
- [NR-222151](https://new-relic.atlassian.net/browse/NR-222151) Extract Server Configuration to resolve IAST localhost connection with application [PR-183](https://github.com/newrelic/csec-java-agent/pull/183)
- [NR-223852](https://new-relic.atlassian.net/browse/NR-223852) Retry IAST request with different endpoint, if failure reason is SSLException or 301 [PR-182](https://github.com/newrelic/csec-java-agent/pull/182)
- [NR-218729](https://new-relic.atlassian.net/browse/NR-218729) Add instrumentation of java.nio.file.Files#setPosixFilePermissions [PR-178](https://github.com/newrelic/csec-java-agent/pull/178)

## [1.1.0] - 2024-1-29
### Changes
- gRPC client v1.4.0+ Support: The security agent now supports gRPC client version 1.4.0 and above (with protobuf-java-utils version 3.0.0 and above)
- gRPC server v1.4.0+ Support: The security agent now supports gRPC server version 1.4.0 and above (with protobuf-java-utils version 3.0.0 and above)
- Add a Logger and Cloud Reporting API for instrumentation modules
- Glassfish Support: The security agent now also supports Glassfish server
- FileIntegrity is marked if any of following is changed - existence, length, permissions, last modified
- Drop RXSS events on the basis of Content-Type Exclusion List
- Akka server v10.0+ Support: The security agent now supports Akka server version 10.0 and above (with scala 2.11 and above)
- Separate out File.exists instrumentation from low-priority instrumentation module
- Removed Schema validation dependency everit-json-schema:1.14.2
- Introduced new dependency commons-collections4:4.4
- Update software license to New Relic Software License Version 1.0

### Fixes
- NR-212335 : support lower case stdout for log_file_name
- NR-215332 : Add java working temp directory to server info for exclusion
- NR-216474 : fix for Null Pointer exception for FILE_OPERATION
- NR-216456 : Fix for Class Cast Exception
- NR-215452 : Added the CC#_id to the completed list empty if absent in case of 2xx or 4xx response
- NR-213477 : Added missing instrumentation for servlet service method
- NR-214326 : Fix class circluarity error generated for BadPaddingException 

## [1.0.8-public-preview] - 2024-1-11
### Changes
- Support for stored procedure call detection in SQL events
- Support for extracting environment variables in case of Remote Code Execution events
- Support for executing script file analysis in case of Remote Code Execution events
- Enabled the transformation of the low-priority instrumentation module by default in case of IAST
- SecureCookie schema check has been removed

### Fixes
- Incorrect user file details in the vulnerability details
- Low severity hook event was not generated when the same url can process multiple request methods
- Detection of server app directory to mitigate false positives for File Access vulnerability

## [1.0.7-public-preview] - 2023-12-6
### Changes
- Async HttpClient v2+ Support: The security agent now also supports Async HTTP client version 2 and above
- Sun Net HTTP Server support: The security agent now supports Sun Net HTTP Server
- Add APM trace information population in the event
- WS headers added : NR-CSEC-ENTITY-GUID & NR-CSEC-ENTITY-NAME
- JSON version bump to 1.1.1
- Add critical error logging via LogMessage event
### Fixes
- Insecure cookie attack vulnerability was flagged in secure communication, accounting communication type to mitigate the issue
- DynamoDB v2 issue: missing attribute values for conditionCheck method in case of transactWriteItems operation on DynamoDB
- Never print LicenseKey 
### Misc
- Updated unit test cases for all the outbound request instrumentation modules to include test cases for csec parent id header
- Unit test cases for Async HttpClient v2+
- Unit test cases for Jetty v12+
- Unit test cases for Sun Net HTTP Server
- Unit test cases for Netty Server

## [1.0.6-public-preview] - 2023-10-17
### Changes
- Cassandra DB v3.0+ Support: The Security agent now supports Cassandra DB version 3.0 and above
- HttpClient v5.0+ Support: The Security agent now also supports HttpClient version 5.0 and above
- Support for std-out logging
- Added feature for Daily log rollover
- Support for logger config: log_file_count and log_limit_in_kbytes
- Relocating all our instrumentation packages under the package com.newrelic.agent.security.instrumentation.*
- Package Refactoring for Unit Tests: Move packaging for all UTs to com.nr.agent.security.instrumentation.*
- Set default value for low severity instrumentation to false

### Fixes
- Fixed ClassNotFoundException for IOStreamHelper class with Glassfish
- Updated PostgreSQL UTs with Embedded Server instead of test container

## [1.0.5-public-preview] - 2023-08-29
### Changes
- [INSTRUMENTATION] Support for Apache log4j 3.0.0-alpha1 (new version released on 21 June 2023)
- [INSTRUMENTATION] Support for Commons.jxpath
- Randomization in WS connection delay
- [FIX] Issue with HealthChecking having empty process stats issue
- Add agent monitoring details and matrix to health check
- Limiting the supported version range for Jetty, due to the new version release of Jetty on 7th Aug, 2023

## [1.0.4-public-preview] - 2023-06-20
### Changes
- Limiting the supported version range for Apache log4j due to the new version release of Apache log4j on 21 June 2023
- Support for indication what all API-IDs are scanned or being scanned.

## [1.0.3-limited-preview] - 2023-05-23
### Changes
- License update
- Improved Logging

## [1.0.2-limited-preview] - 2023-05-19
### Added
- [LOGGER] Update init logger : maintain consistncy with all security agents
- [INSTRUMENTATION] Support for Embedded Jetty 9 & 11
- Added low priority instrumentations, turned off by default.
- Set WS thread names to start with NR-CSEC-
- Migrated build & release pipeline to GHA
- Added instrumentation and unit test cases for SQL batch operations
- Low severity event filter cleanup with 30 min interval.
- Added unit test cases for following:
    - Servlet 2.4, 5.0, 6.0
- Applied instrumentation priority changes
- Scheduler for FileCleaner

### Fixed
- NPE fix in unit test of R2DBC
- Amazon DynamoDB unit test 
- Make Amazon dynamodb unit test aarch64 comaptible
- Change hash int to set in introspector API of instrumentation unit tests.
- NR-118286 : case 1 : snapshot dir should be created always inside logs of nr-security-home
- Compatibility fix for file-operation instrumentation modules unit test in linux env.
- Move File exist hook to low priority instrumentation module
- Skip hook processing on Servlet low priority instrumentations modules
- Skip hook processing on internal threads
- Changes for IAST data pull (on demand #CC request)
- Removal of tmp file created for IAST scanning.
- First HC to be sent after 30 sec of thread launch
- Removed @NewField from Nashorn Instrumentation with Transaction map logic to avoid OOM issue

## [1.0.1-limited-preview] - 2023-04-20

### Added
- More instrumentations added wrt to APM
- Thread Name Changes from K2 to NR-CSEC
- Non-Blocking initial WS connection to address NR-107536 : APM Integration test failure due to WS

### Fixed
- Add handling for passing the license key in quotes
- NR-103217 Events for jetty 9 not getting generated.
- NR-103233, removed dependency of java.lang.management by oshi library.
- Minor fix to URLConnection_Instrumentation regarding empty url.
- NR-93687, add excludes of Specific InputStream classes, invoke getTransaction for preload of Transaction classes
- Xpath update incorrect return types of inst methods
- Removed java.io.FileSystem Hooks since those are covered in java.io.File inst. Works around NR-98829
- NR-106418, update JSON converter to include null values also.


## [1.0.0-limited-preview] - 2023-02-23

### Added
- Add debug level env variables for log file size and count manipulations NR_CSEC_DEBUG_LOGFILE_SIZE & NR_CSEC_DEBUG_LOGFILE_MAX_COUNT
- Rename healthcheck field from stat to stats
- Websocket connection now support custom ca certificate
- Added data member isIASTRequest in base of JavaAgentEventBean
- Changes to APM code: now only loading CSEC components if agent config has ‘security.enable’ value defined.
- Changes to user code detection hooks in CSEC. Now able to point servlet annotated classes and extension of HttpServlet do* methods.
- Fixed verify error with all mongo version, added instrumentation for mongo 3.1.x
- Added Let's Encrypt CA to trust store for prod clusters.
- Added options to provide custom trust CA via agent config('security.ca_bundle_path') and env parameter('NEW_RELIC_SECURITY_CA_BUNDLE_PATH'). This var takes path accessible to collector and expects a pem file.
- Reset CSEC component version to 1.0.0
- Reset CSEC json version to 1.0.0
- Set WS TCP connect timeout to 15
- Update WS header to include correct NR-LICENSE-KEY & NR-AGENT-RUN-TOKEN
