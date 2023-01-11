package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import org.apache.commons.lang3.RegExUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.unbescape.html.HtmlEscape;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CallbackUtils {

    private static final String HTML_COMMENT_END = "-->";
    private static final String HTML_COMMENT_START = "!--";
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String ANGLE_END = ">";
    public static final String JAVASCRIPT = "javascript:";
    public static final String ERROR = "Error :";
    public static final String FIVE_COLON = "::::";
    public static final String APPLICATION_JSON = "application/json";
    public static final String APPLICATION_XML = "application/xml";
    public static final String APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded";
    public static final String SCRIPT = "script";
    public static final String SCRIPT_END = "</script";
    public static final String ON1 = "on";
    public static final String SRC = "src";
    public static final String HREF = "href";
    public static final Character ANGLE_END_CHAR = '>';
    public static final String ACTION = "action";
    public static final String EQUALS = "=";
    public static final String ANGLE_START = "<";
    public static final String FORMACTION = "formaction";
    public static final String SRCDOC = "srcdoc";
    public static final String DATA = "data";
    public static final String CAME_TO_XSS_CHECK = "Came to XSS check : ";
    private static final Pattern REGEX_SPACE = Pattern.compile("\\s+");

    public static Pattern tagNameRegex = Pattern.compile("<([a-zA-Z_\\-]+[0-9]*|!--)",
            Pattern.MULTILINE | Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    public static Pattern attribRegex = Pattern.compile(
            "([^(\\/\\s<'\">)]+?)(?:\\s*)=\\s*(('|\")([\\s\\S]*?)(?:(?=(\\\\?))\\5.)*?\\3|.+?(?=\\/>|>|\\?>|\\s|<\\/|$))",
            Pattern.MULTILINE | Pattern.CASE_INSENSITIVE | Pattern.DOTALL);


    // TODO: use complete response instead of just response body.
    public static Set<String> checkForReflectedXSS(HttpRequest httpRequest, HttpResponse httpResponse) {
        Set<String> toReturn = new HashSet<>();

        Set<String> combinedRequestData = decodeRequestData(httpRequest);
        if (combinedRequestData.isEmpty()) {
            toReturn.add(StringUtils.EMPTY);
            return toReturn;
        }
        Set<String> combinedResponseData = decodeResponseData(httpResponse);
        if (combinedResponseData.isEmpty()) {
            toReturn.add(StringUtils.EMPTY);
            return toReturn;
        }
        String combinedResponseDataString = StringUtils.joinWith(FIVE_COLON, combinedResponseData);

        logger.log(LogLevel.DEBUG, String.format("Checking reflected XSS : %s :: %s", combinedRequestData, combinedResponseDataString), CallbackUtils.class.getName());

        Set<String> attackContructs = isXSS(combinedRequestData);

        for (String construct : attackContructs) {
            if (StringUtils.containsIgnoreCase(combinedResponseDataString, construct)) {
                toReturn.add(construct);

                if (!(AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                        && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled())) {
                    break;
                }
            }
        }
        if (toReturn.isEmpty()) {
            toReturn.add(StringUtils.EMPTY);
        }
        return toReturn;
    }

    /**
     * Method to url decode given encodedString under UTF-8 encoding. If the
     * conversion is not possible, <code>original string</code> is returned.
     *
     * @param encodedString URL encoded string
     * @return URL decoded string
     */
    public static String urlDecode(String encodedString) {
        String decodedString = StringUtils.EMPTY;
        try {
            decodedString = URLDecoder.decode(encodedString, StandardCharsets.UTF_8.name());
        } catch (Throwable e) {
            decodedString = encodedString;
        }
        return decodedString;
    }


    static Set<String> getXSSConstructs(String data) {
        logger.log(LogLevel.DEBUG, CAME_TO_XSS_CHECK + data, CallbackUtils.class.getName());
        List<String> construct = new ArrayList<>();
        boolean isAttackConstruct = false;

        // indicates the actual current position in the data where the processing ptr is.
        int currPos = 0;

        //
        int startPos = 0;

        //
        int tmpCurrPos = 0;

        //
        int tmpStartPos = 0;

        // iterate over the complete data string.
        while (currPos < data.length()) {
            Matcher matcher = tagNameRegex.matcher(data);
            if (!matcher.find(currPos)) {
                return new HashSet<>(construct);
            }
            isAttackConstruct = false;
            String tagName = matcher.group(1);
            if (StringUtils.isBlank(tagName)) {
                return new HashSet<>(construct);
            }
            startPos = matcher.start();
            currPos = matcher.end() - 1;
            if (StringUtils.equals(HTML_COMMENT_START, tagName)) {
                tmpCurrPos = StringUtils.indexOf(data, HTML_COMMENT_END, startPos);
                if (tmpCurrPos == -1) {
                    break;
                } else {
                    currPos = tmpCurrPos;
                    continue;
                }
            }
            tmpStartPos = tmpCurrPos = StringUtils.indexOf(data, ANGLE_END, startPos);

            if (tmpCurrPos == -1) {
                tmpStartPos = startPos;
            }

            Matcher attribMatcher = attribRegex.matcher(data);
            while (attribMatcher.find(currPos)) {
                String attribData = attribMatcher.group().trim();
                currPos = attribMatcher.end() - 1;
                tmpCurrPos = StringUtils.indexOf(data, ANGLE_END, tmpStartPos);

                if ((tmpCurrPos == -1 || attribMatcher.start() < tmpCurrPos)) {
                    tmpStartPos = tmpCurrPos = attribMatcher.end() - 1;
                    tmpStartPos++;
                    if (StringUtils.isBlank(attribMatcher.group(3)) && attribMatcher.end() >= tmpCurrPos) {
                        tmpStartPos = tmpCurrPos = StringUtils.indexOf(data, ANGLE_END, attribMatcher.start());
                        if (tmpStartPos == -1) {
                            tmpStartPos = data.length() - 1;
                        }
                        attribData = StringUtils.substring(attribData, 0, tmpStartPos);
                    }

                    String key = StringUtils.substringBefore(attribData, EQUALS);
                    String val = StringUtils.substringAfter(attribData, EQUALS);

                    if (StringUtils.isNotBlank(key) && (StringUtils.startsWithIgnoreCase(key, ON1)
                            || StringUtils.equalsIgnoreCase(key, SRC) || StringUtils.equalsIgnoreCase(key, HREF)
                            || StringUtils.equalsIgnoreCase(key, ACTION)
                            || StringUtils.equalsIgnoreCase(key, FORMACTION)
                            || StringUtils.equalsIgnoreCase(key, SRCDOC) || StringUtils.equalsIgnoreCase(key, DATA)
                            || StringUtils.containsIgnoreCase(
                            RegExUtils.removeAll(HtmlEscape.unescapeHtml(val), REGEX_SPACE), JAVASCRIPT))) {
                        isAttackConstruct = true;
                    }
                } else {
                    break;
                }
            }
            if (tmpCurrPos > 0) {
                currPos = tmpCurrPos;
            }
            if (data.charAt(currPos) != ANGLE_END_CHAR) {
                int tmp = StringUtils.indexOf(data, ANGLE_END, currPos);

                if (tmp != -1) {
                    currPos = tmp;
                } else if (!isAttackConstruct) {
                    continue;
                }
            }
            if (StringUtils.equalsIgnoreCase(tagName.trim(), SCRIPT)) {
                int locationOfEndTag = StringUtils.indexOfIgnoreCase(data, SCRIPT_END, currPos);
                if (locationOfEndTag != -1) {
                    String body = StringUtils.substring(data, currPos + 1, locationOfEndTag);
                    if (StringUtils.isNotBlank(body)) {
                        construct.add(StringUtils.substring(data, startPos, currPos + 1) + body);

                        continue;
                    }
                } else {
                    String body = StringUtils.substring(data, currPos + 1);
                    int tagEnd = StringUtils.indexOf(body, ANGLE_END);
                    if (StringUtils.isNotBlank(body) && tagEnd != -1) {
                        body = StringUtils.substring(body, tagEnd);
                        construct.add(StringUtils.substring(data, startPos, currPos + 1) + body);
                        break;
                    }
                }
            }

            if (isAttackConstruct) {
                construct.add(StringUtils.substring(data, startPos, currPos + 1));
            }
        }
        return new HashSet<>(construct);
    }

    public static Set<String> isXSS(Set<String> combinedData) {
        Set<String> attackConstructs = new HashSet<>();
        for (String data : combinedData) {
            attackConstructs.addAll(getXSSConstructs(data));
        }
        return attackConstructs;
    }

    public static Set<String> decodeResponseData(HttpResponse httpResponse) {
        Set<String> processedData = new HashSet<>();
        String contentType = httpResponse.getResponseContentType();
        String responseBody = httpResponse.getResponseBody().toString();
        String processedBody = responseBody;


        try {
            processedData.add(processedBody);

            String oldProcessedBody;

            if (StringUtils.isNoneEmpty(responseBody)) {
                switch (contentType) {
                    case APPLICATION_JSON:
                        do {
                            oldProcessedBody = processedBody;
                            processedBody = StringEscapeUtils.unescapeJson(processedBody);
                            if (!StringUtils.equals(oldProcessedBody, processedBody)) {
                                processedData.add(processedBody);
                                // System.out.println("Decoding JSON: " + processedBody);
                            }
                        } while (!StringUtils.equals(oldProcessedBody, processedBody));
                        break;
                    case APPLICATION_XML:
                        do {
                            oldProcessedBody = processedBody;
                            processedBody = StringEscapeUtils.unescapeXml(processedBody);
                            if (!StringUtils.equals(oldProcessedBody, processedBody)) {
                                processedData.add(processedBody);
                                // System.out.println("Decoding XML: " + processedBody);
                            }
                        } while (!StringUtils.equals(oldProcessedBody, processedBody));
                        break;

                }
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR, e, CallbackUtils.class.getName());
        }
        return processedData;
    }

    public static Set<String> decodeRequestData(HttpRequest httpRequest) {
        Set<String> processedData = new HashSet<>();
        String contentType = httpRequest.getContentType();
        String body = httpRequest.getBody().toString();
        String processedBody = body;

        try {

            // Process & add header keys & values separately.
            Map<String, String> headerCopy = new HashMap<>((Map<String, String>) httpRequest.getHeaders());
            headerCopy.remove("k2-fuzz-request-id");
            for (Entry<String, String> entry : headerCopy.entrySet()) {
                // For key
                processURLEncodedDataForXSS(processedData, entry.getKey());

                // For Value
                processURLEncodedDataForXSS(processedData, entry.getValue());
            }

            // Process ParameterMap
            if (httpRequest.getParameterMap() != null) {
                System.out.println(httpRequest.getParameterMap());
                for (Entry<String, String[]> entry : httpRequest.getParameterMap().entrySet()) {
                    if (StringUtils.contains(entry.getKey(), ANGLE_START)) {
                        processedData.add(entry.getKey());
                    }
                    for (String val : entry.getValue()) {
                        if (StringUtils.contains(val, ANGLE_START)) {
                            processedData.add(val);
                        }
                    }
                }
            }

            // For URL
            processURLEncodedDataForXSS(processedData, httpRequest.getUrl());


            if (StringUtils.isNotBlank(processedBody)) {
                // Process body
                processedData.add(processedBody);
                String oldProcessedBody;
                switch (contentType) {
                    case APPLICATION_JSON:
//					do {
                        oldProcessedBody = processedBody;
                        processedBody = StringEscapeUtils.unescapeJson(processedBody);
                        if (!StringUtils.equals(oldProcessedBody, processedBody)
                                && StringUtils.contains(processedBody, ANGLE_START)) {
                            processedData.add(processedBody);
                            // System.out.println("Decoding JSON: " + processedBody);
                        }
//					} while (!StringUtils.equals(oldProcessedBody, processedBody));
                        break;
                    case APPLICATION_XML:
//					do {
                        oldProcessedBody = processedBody;
                        processedBody = StringEscapeUtils.unescapeXml(processedBody);
                        if (!StringUtils.equals(oldProcessedBody, processedBody)
                                && StringUtils.contains(processedBody, ANGLE_START)) {
                            processedData.add(processedBody);
                            // System.out.println("Decoding XML: " + processedBody);
                        }
//					} while (!StringUtils.equals(oldProcessedBody, processedBody));
                        break;

                    case APPLICATION_X_WWW_FORM_URLENCODED:
                        processedBody = urlDecode(processedBody);
                        processedData.add(processedBody);

//					do {
                        oldProcessedBody = processedBody;
                        processedBody = urlDecode(processedBody);
                        if (!StringUtils.equals(oldProcessedBody, processedBody)
                                && StringUtils.contains(processedBody, ANGLE_START)) {
                            processedData.add(processedBody);
                            // System.out.println("Decoding URL: " + processedBody);
                        }
//					} while (!StringUtils.equals(oldProcessedBody, processedBody));

                        break;
                }

            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR, e, CallbackUtils.class.getName());
        }
        return processedData;
    }

    private static void processURLEncodedDataForXSS(Set<String> processedData, String data) {
        String key = data;
        if (StringUtils.contains(key, ANGLE_START)) {
            processedData.add(key);
        }
        key = urlDecode(key);
        if (StringUtils.contains(key, ANGLE_START)) {
            processedData.add(key);
        }
    }

}