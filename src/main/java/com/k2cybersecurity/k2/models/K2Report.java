package com.k2cybersecurity.k2.models;

public class K2Report {

	private String attackTime;

	private String iP;

	private String attackDescription;

	private String incidentID;

	private String fileName;

	private String hTTPMethod;

	private String methodName;

	private String lineNumber;

	private String applicationName;

	private String ports;

	private String hTTPURL;

	private String executedQueryOrCommand;

	private String parameterMap;

	private String cookie;

	private String syscall;

	private String syscallModule;

	private String zerodayApplication;

	public String getAttackTime() {
		return attackTime;
	}

	public void setAttackTime(String attackTime) {
		this.attackTime = attackTime;
	}

	public String getiP() {
		return iP;
	}

	public void setiP(String iP) {
		this.iP = iP;
	}

	public String getAttackDescription() {
		return attackDescription;
	}

	public void setAttackDescription(String attackDescription) {
		this.attackDescription = attackDescription;
	}

	public String getIncidentID() {
		return incidentID;
	}

	public void setIncidentID(String incidentID) {
		this.incidentID = incidentID;
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public String gethTTPMethod() {
		return hTTPMethod;
	}

	public void sethTTPMethod(String hTTPMethod) {
		this.hTTPMethod = hTTPMethod;
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

	public String getApplicationName() {
		return applicationName;
	}

	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}

	public String getPorts() {
		return ports;
	}

	public void setPorts(String ports) {
		this.ports = ports;
	}

	public String gethTTPURL() {
		return hTTPURL;
	}

	public void sethTTPURL(String hTTPURL) {
		this.hTTPURL = hTTPURL;
	}

	public String getExecutedQueryOrCommand() {
		return executedQueryOrCommand;
	}

	public void setExecutedQueryOrCommand(String executedQueryOrCommand) {
		this.executedQueryOrCommand = executedQueryOrCommand;
	}

	public String getParameterMap() {
		return parameterMap;
	}

	public void setParameterMap(String parameterMap) {
		this.parameterMap = parameterMap;
	}

	public String getCookie() {
		return cookie;
	}

	public void setCookie(String cookie) {
		this.cookie = cookie;
	}

	public String getSyscall() {
		return syscall;
	}

	public void setSyscall(String syscall) {
		this.syscall = syscall;
	}

	public String getSyscallModule() {
		return syscallModule;
	}

	public void setSyscallModule(String syscallModule) {
		this.syscallModule = syscallModule;
	}

	public String getZerodayApplication() {
		return zerodayApplication;
	}

	public void setZerodayApplication(String zerodayApplication) {
		this.zerodayApplication = zerodayApplication;
	}

	@Override
	public String toString() {
		return "k2report [attackTime=" + attackTime + ", iP=" + iP + ", attackDescription=" + attackDescription
				+ ", incidentID=" + incidentID + ", fileName=" + fileName + ", method=" + hTTPMethod + ", methodName="
				+ methodName + ", lineNumber=" + lineNumber + ", applicationName=" + applicationName + ", ports="
				+ ports + ", hTTPURL=" + hTTPURL + ", executedQueryOrCommand=" + executedQueryOrCommand
				+ ", parameterMap=" + parameterMap + ", cookie=" + cookie + ", syscall=" + syscall + ", syscallModule="
				+ syscallModule + ", zerodayApplication=" + zerodayApplication + "]";
	}

}
