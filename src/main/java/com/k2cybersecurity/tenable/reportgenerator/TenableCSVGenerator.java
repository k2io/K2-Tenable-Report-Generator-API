package com.k2cybersecurity.tenable.reportgenerator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.k2.models.K2Report;
import com.k2cybersecurity.tenable.models.TenableReport;

public class TenableCSVGenerator {
	private static int tenableCount;
	private static int tenableInformationCount;
	private static int tenableLowCount;
	private static int tenableMediumCount;
	private static int tenableHighCount;
	private static int tenableCriticalCount;
	private static int k2HighCount;
	private static Map<String, Integer> summaryMap = new HashMap<String, Integer>();

	private static void countTenableVulnerabilties(List<TenableReport> tenableReports) {
		for (TenableReport tenableReport : tenableReports) {
			if (StringUtils.equals(tenableReport.getRisk(), "Informational")) {
				tenableInformationCount++;
			} else if (StringUtils.equals(tenableReport.getRisk(), "Low")) {
				tenableLowCount++;
			} else if (StringUtils.equals(tenableReport.getRisk(), "Medium")) {
				tenableMediumCount++;
			} else if (StringUtils.equals(tenableReport.getRisk(), "Critical")) {
				tenableCriticalCount++;
			} else if (StringUtils.equals(tenableReport.getRisk(), "High")) {
				tenableHighCount++;
			}
		}

		summaryMap.put("tenableInformationCount", tenableInformationCount);
		summaryMap.put("tenableLowCount", tenableLowCount);
		summaryMap.put("tenableMediumCount", tenableMediumCount);
		summaryMap.put("tenableHighCount", tenableHighCount);
		summaryMap.put("tenableCriticalCount", tenableCriticalCount);

		tenableCount = tenableReports.size();
		summaryMap.put("tenableCount", tenableCount);
	}

	private static void countK2Attacks(List<K2Report> k2Reports) {
		summaryMap.put("k2HighCount", k2Reports.size());
	}

	private static void addSummaryInFinalReport(List<TenableReport> tenableReports) {
		String finalMessage = "Summary\n=========\n\nTenable:\nTotal Vulnerabilities = " + tenableCount
				+ "\nInformational Vulnerabilities = " + tenableInformationCount + "\nLow Risk Vulnerabilities = "
				+ tenableLowCount + "\nMedium Risk Vulnerabilities = " + tenableMediumCount
				+ "\nHigh Risk Vulnerabilities = " + tenableHighCount + "\nCritical Risk Vulnerabilities = "
				+ tenableCriticalCount + "\n\nK2:\n" + "High Risk Attacks = " + k2HighCount;

		TenableReport tr = new TenableReport();
		tr.setPluginID("Summary");
		tr.setDescription(finalMessage);
		tenableReports.add(0, tr);
	}

	private static void addAttacksFoundByOnlyK2InCSV(List<TenableReport> tenableReports, List<K2Report> k2Reports) {
		int counter = 0;

		for (K2Report k2Report : k2Reports) {
			TenableReport tr = new TenableReport();
			tr.setPluginID("K2");
			tr.setcVSS("7.5");
			tr.setRisk("High");
			tr.setHost(k2Report.getiP());
			tr.setProtocol("TCP");
			tr.setPort(StringUtils.split(k2Report.getPorts(), ',')[0]);
			tr.setName(k2Report.getAttackDescription());
			tr.setSynopsis(k2Report.getAttackDescription());

			String output = "";
			output += "Vulnerability : " + k2Report.getAttackDescription();
			output += "\nPath : " + k2Report.gethTTPURL();
			output += "\nFinding ID: " + k2Report.getIncidentID();
			output += "\nRisk : High";
			output += "\nFile Name : " + k2Report.getFileName();
			output += "\nMethod Name : " + k2Report.getMethodName();
			output += "\nLine Number : " + k2Report.getLineNumber();
			output += "\nParameters : " + k2Report.getParameterMap();
			output += "\nExecuted Query/Command : " + k2Report.getExecutedQueryOrCommand();

			tr.setK2output(output);
			tenableReports.add(counter++, tr);
		}
	}

	public static void run(List<TenableReport> tenableReports, List<K2Report> k2Reports, String OUTPUT_DIR) {

		countTenableVulnerabilties(tenableReports);

		countK2Attacks(k2Reports);

		addAttacksFoundByOnlyK2InCSV(tenableReports, k2Reports);

		addSummaryInFinalReport(tenableReports);

		TenableCSVWriter.writeMergedReport(tenableReports, OUTPUT_DIR);
	}

}
