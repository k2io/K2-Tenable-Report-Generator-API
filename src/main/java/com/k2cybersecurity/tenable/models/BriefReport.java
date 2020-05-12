package com.k2cybersecurity.tenable.models;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class BriefReport {

	private String url;

	private boolean isDetctedByK2;

	private boolean isDetctedByTenable;

	private Set<String> k2ReportedAttacks = new HashSet<String>();

	private Set<String> tenableReportedAttacks = new HashSet<String>();

	private String remarks;

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public boolean isDetctedByK2() {
		return isDetctedByK2;
	}

	public void setDetctedByK2(boolean isDetctedByK2) {
		this.isDetctedByK2 = isDetctedByK2;
	}

	public boolean isDetctedByTenable() {
		return isDetctedByTenable;
	}

	public void setDetctedByTenable(boolean isDetctedByTenable) {
		this.isDetctedByTenable = isDetctedByTenable;
	}

	public Set<String> getK2ReportedAttacks() {
		return k2ReportedAttacks;
	}

	public void setK2ReportedAttacks(Set<String> k2ReportedAttacks) {
		this.k2ReportedAttacks = k2ReportedAttacks;
	}

	public Set<String> getTenableReportedAttacks() {
		return tenableReportedAttacks;
	}

	public void setTenableReportedAttacks(Set<String> tenableReportedAttacks) {
		this.tenableReportedAttacks = tenableReportedAttacks;
	}

	public String getRemarks() {
		return remarks;
	}

	public void setRemarks(String remarks) {
		this.remarks = remarks;
	}

	@Override
	public String toString() {
		return "BriefReport [url=" + url + ", isDetctedByK2=" + isDetctedByK2 + ", isDetctedByTenable="
				+ isDetctedByTenable + ", k2ReportedAttacks=" + k2ReportedAttacks + ", tenableReportedAttacks="
				+ tenableReportedAttacks + ", remarks=" + remarks + "]";
	}

}
