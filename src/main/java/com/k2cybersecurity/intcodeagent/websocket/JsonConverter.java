package com.k2cybersecurity.intcodeagent.websocket;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Collections;

import org.json.simple.JSONArray;

import com.k2cybersecurity.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;

public class JsonConverter {

	private static final String JSON_SEPRATER = "\":";
	private static final String STR_FORWARD_SLASH = "\"";
	private static final String STR_COMMA = ",";
	private static final String STR_END_CUELY_BRACKET = "}";
	private static final String STR_START_CUELY_BRACKET = "{";

	public static String toJSON(Object obj) {
		StringBuilder jsonString = new StringBuilder(STR_START_CUELY_BRACKET);

		Class<?> objClass = obj.getClass();
		Class<?> superClass = obj.getClass().getSuperclass();

		Field[] superFields = superClass.getDeclaredFields();
		if (superFields.length > 1) {
			jsonString.append(getFieldsAsJsonString(superFields, obj));
			jsonString.append(STR_COMMA);
		}
		Field[] objFields = objClass.getDeclaredFields();
		jsonString.append(getFieldsAsJsonString(objFields, obj));
		jsonString.append(STR_END_CUELY_BRACKET);
		return jsonString.toString();
	}

	private static String getFieldsAsJsonString(Field[] fields, Object obj) {
		StringBuilder jsonString = new StringBuilder();
		for (int i = 0; i < fields.length; i++) {
			try {
				if (!Modifier.isStatic(fields[i].getModifiers())) {
					Field field = fields[i];
					field.setAccessible(true);
					Object value = field.get(obj);
					if (value != null) {
						jsonString.append(STR_FORWARD_SLASH);
						jsonString.append(field.getName());
						jsonString.append(JSON_SEPRATER);
						if (field.getType().equals(String.class)) {
							jsonString.append(STR_FORWARD_SLASH);
							jsonString.append(value);
							jsonString.append(STR_FORWARD_SLASH);
						} else if (field.getType().isPrimitive()) {
							jsonString.append(value);
						} else {
							jsonString.append(value.toString());
						}
						jsonString.append(STR_COMMA);
					}
				}
			} catch (IllegalArgumentException | IllegalAccessException e) {
				e.printStackTrace();
			}
		}

		jsonString.deleteCharAt(jsonString.length() - 1);
		return jsonString.toString();
	}

//	public static void main(String[] args) {
//
//		String[] arr = new String[] {"as", "vd"};
//
//
//		JavaAgentEventBean javaAgentEventBean = new JavaAgentEventBean(System.currentTimeMillis(), 15L, "source", 12121,
//				"asdasd-1212-sdf", "12-12", VulnerabilityCaseType.DB_COMMAND);
//		JSONArray jsonArray = new JSONArray();
//		jsonArray.add("sadasda");
//		jsonArray.add("sadasdaasdfasd");
//		jsonArray.addAll(Arrays.asList(arr));
//		javaAgentEventBean.setParameters(jsonArray);
//
//		ServletInfo servletInfo = new ServletInfo();
//		servletInfo.setDataTruncated(false);
//		servletInfo.setRawRequest("sdasdfasfasf \n\r asd \r\n asd asd asd ");
//		javaAgentEventBean.setServletInfo(servletInfo);
//
//		System.out.println(javaAgentEventBean.toString());
//	}
}
