package com.k2cybersecurity.tenable.models;

public class TenableReport {
	private String pluginID;

	private String cVE;

	private String cVSS;

	private String risk;

	private String host;

	private String protocol;

	private String port;

	private String name;

	private String synopsis;

	private String description;

	private String solution;

	private String seeAlso;

	private String pluginOutput;

	private TenablePluginOutput tenablePluginOutput;

	private String k2output;

	public String getPluginID() {
		return pluginID;
	}

	public void setPluginID(String pluginID) {
		this.pluginID = pluginID;
	}

	public String getcVE() {
		return cVE;
	}

	public void setcVE(String cVE) {
		this.cVE = cVE;
	}

	public String getcVSS() {
		return cVSS;
	}

	public void setcVSS(String cVSS) {
		this.cVSS = cVSS;
	}

	public String getRisk() {
		return risk;
	}

	public void setRisk(String risk) {
		this.risk = risk;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public String getPort() {
		return port;
	}

	public void setPort(String port) {
		this.port = port;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getSynopsis() {
		return synopsis;
	}

	public void setSynopsis(String synopsis) {
		this.synopsis = synopsis;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getSolution() {
		return solution;
	}

	public void setSolution(String solution) {
		this.solution = solution;
	}

	public String getSeeAlso() {
		return seeAlso;
	}

	public void setSeeAlso(String seeAlso) {
		this.seeAlso = seeAlso;
	}

	public String getPluginOutput() {
		return pluginOutput;
	}

	public void setPluginOutput(String pluginOutput) {
		this.pluginOutput = pluginOutput;
	}

	public TenablePluginOutput getTenablePluginOutput() {
		return tenablePluginOutput;
	}

	public void setTenablePluginOutput(TenablePluginOutput tenablePluginOutput) {
		this.tenablePluginOutput = tenablePluginOutput;
	}

	public String getK2output() {
		return k2output;
	}

	public void setK2output(String k2output) {
		this.k2output = k2output;
	}

	@Override
	public String toString() {
		return "TenableReport [pluginID=" + pluginID + ", cVE=" + cVE + ", cVSS=" + cVSS + ", risk=" + risk + ", host="
				+ host + ", protocol=" + protocol + ", port=" + port + ", name=" + name + ", synopsis=" + synopsis
				+ ", description=" + description + ", solution=" + solution + ", seeAlso=" + seeAlso + ", pluginOutput="
				+ pluginOutput + ", tenablePluginOutput=" + tenablePluginOutput + ", k2output=" + k2output + "]";
	}

}
