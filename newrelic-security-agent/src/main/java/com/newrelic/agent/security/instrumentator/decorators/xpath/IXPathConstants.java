package com.newrelic.agent.security.instrumentator.decorators.xpath;

public interface IXPathConstants {

    String GET_INTERNAL_EXPRESSION = "getInternalExpression";
    String M_PATTERN_STRING = "m_patternString";
    String XPATH_EXECUTE_METHOD1 = "public org.apache.xpath.objects.XObject org.apache.xpath.XPath.execute(org.apache.xpath.XPathContext,int,org.apache.xml.utils.PrefixResolver) throws javax.xml.transform.TransformerException";
    String XPATH_EXECUTE_METHOD2 = "public com.sun.org.apache.xpath.internal.objects.XObject com.sun.org.apache.xpath.internal.XPath.execute(com.sun.org.apache.xpath.internal.XPathContext,int,com.sun.org.apache.xml.internal.utils.PrefixResolver) throws javax.xml.transform.TransformerException";
    String XPATH_DOM4J_READER = "public void org.jaxen.saxpath.base.XPathReader.parse(java.lang.String) throws org.jaxen.saxpath.SAXPathException";


}
