package com.k2cybersecurity.k2.models;

import java.util.Map;

public class K2MinifiedOutput {

	private String hTTPURL;

	private String attackDescription;

	private String fileName;

	private String methodName;

	private String lineNumber;

	private String parameterMap;

	public String gethTTPURL() {
		return hTTPURL;
	}

	public void sethTTPURL(String hTTPURL) {
		this.hTTPURL = hTTPURL;
	}

	public String getAttackDescription() {
		return attackDescription;
	}

	public void setAttackDescription(String attackDescription) {
		this.attackDescription = attackDescription;
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public String getMethodName() {
		return methodName;
	}

	public void setMethodName(String methodName) {
		this.methodName = methodName;
	}

	public String getLineNumber() {
		return lineNumber;
	}

	public void setLineNumber(String lineNumber) {
		this.lineNumber = lineNumber;
	}

	public String getParameterMap() {
		return parameterMap;
	}

	public void setParameterMap(String parameterMap) {
		this.parameterMap = parameterMap;
	}

	@Override
	public String toString() {
		return "\nHTTP URL : " + hTTPURL + "\nAttack Description : " + attackDescription + "\nFile Name : "
				+ fileName + "\nMethod Name : " + methodName + "\nLine Number : " + lineNumber + "\nParameterMap : \n"
				+ parameterMap + "\n";
	}

}
