package com.k2cybersecurity.tenable.models;

import java.util.List;

import com.k2cybersecurity.k2.models.K2Report;

public class CombinedMapValue {

	private List<TenableReport> tenableReports;

	private List<K2Report> k2Reports;

	private boolean isDetectedByK2;

	private boolean isDetectedByTenable;

	public List<TenableReport> getTenableReports() {
		return tenableReports;
	}

	public void setTenableReports(List<TenableReport> tenableReports) {
		this.tenableReports = tenableReports;
	}

	public List<K2Report> getK2Reports() {
		return k2Reports;
	}

	public void setK2Reports(List<K2Report> k2Reports) {
		this.k2Reports = k2Reports;
	}

	public boolean isDetectedByK2() {
		return isDetectedByK2;
	}

	public void setDetectedByK2(boolean isDetectedByK2) {
		this.isDetectedByK2 = isDetectedByK2;
	}

	public boolean isDetectedByTenable() {
		return isDetectedByTenable;
	}

	public void setDetectedByTenable(boolean isDetectedByTenable) {
		this.isDetectedByTenable = isDetectedByTenable;
	}

}
