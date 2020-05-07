package com.k2cybersecurity.tenable.models;

import java.util.Map;

public class TenablePluginOutput {

	private String url;
	
	private Map<String, String> detectionInformation;
	
	private String proof;
	
	private String request;
	
	private String response;

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public Map<String, String> getDetectionInformation() {
		return detectionInformation;
	}

	public void setDetectionInformation(Map<String, String> detectionInformation) {
		this.detectionInformation = detectionInformation;
	}

	public String getProof() {
		return proof;
	}

	public void setProof(String proof) {
		this.proof = proof;
	}

	public String getRequest() {
		return request;
	}

	public void setRequest(String request) {
		this.request = request;
	}

	public String getResponse() {
		return response;
	}

	public void setResponse(String response) {
		this.response = response;
	}

	@Override
	public String toString() {
		return "TenablePluginOutput [url=" + url + ", detectionInformation=" + detectionInformation + ", proof=" + proof
				+ ", request=" + request + ", response=" + response + "]";
	}
	
	
	
}
