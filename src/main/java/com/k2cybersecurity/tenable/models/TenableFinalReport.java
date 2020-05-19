package com.k2cybersecurity.tenable.models;

import java.util.List;

import javax.swing.text.html.MinimalHTMLWriter;

import com.k2cybersecurity.k2.models.K2MinifiedOutput;

public class TenableFinalReport {

	private TenableReport tenableReport;

	private List<K2MinifiedOutput> bothDetected;

	private List<K2MinifiedOutput> additionalFindings;

	public TenableReport getTenableReport() {
		return tenableReport;
	}

	public void setTenableReport(TenableReport tenableReport) {
		this.tenableReport = tenableReport;
	}

	public List<K2MinifiedOutput> getBothDetected() {
		return bothDetected;
	}

	public void setBothDetected(List<K2MinifiedOutput> bothDetected) {
		this.bothDetected = bothDetected;
	}

	public List<K2MinifiedOutput> getAdditionalFindings() {
		return additionalFindings;
	}

	public void setAdditionalFindings(List<K2MinifiedOutput> additionalFindings) {
		this.additionalFindings = additionalFindings;
	}

}
