package com.k2cybersecurity.tenable.reportgenerator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;

import com.k2cybersecurity.k2.models.K2Report;
import com.k2cybersecurity.tenable.models.CombinedMapValue;
import com.k2cybersecurity.tenable.models.TenableReport;

public class TenablePdfGenerator {
	private static Map<String, Integer> sumMap = new HashMap<String, Integer>();
	private static Map<ImmutablePair<String, String>, CombinedMapValue> endReport = new HashMap<ImmutablePair<String, String>, CombinedMapValue>();
	private static Map<String, List<String>> vulApis = new HashMap<String, List<String>>();

	private static void prepareEndReport(List<TenableReport> tenableReports, List<K2Report> k2Reports) {
		for (TenableReport tenableReport : tenableReports) {
			if (StringUtils.equals(tenableReport.getRisk(), "Critical")
					|| StringUtils.equals(tenableReport.getRisk(), "High")) {
				String url = null;
				String uri = null;
				if (tenableReport.getTenablePluginOutput().getUrl() != null) {
					url = tenableReport.getTenablePluginOutput().getUrl();
					uri = StringUtils.substring(url, StringUtils.ordinalIndexOf(url, "/", 3));
				} else {
					uri = "NA";
				}
				ImmutablePair<String, String> pair = new ImmutablePair<String, String>(uri, tenableReport.getName());

				if (endReport.containsKey(pair)) {
					CombinedMapValue combinedMapValue = endReport.get(pair);
					if (combinedMapValue.getTenableReports().size() > 0) {
						combinedMapValue.getTenableReports().add(tenableReport);
					} else {
						combinedMapValue.setTenableReports(new ArrayList<TenableReport>());
					}
				} else {
					CombinedMapValue combinedMapValue = new CombinedMapValue();
					combinedMapValue.setTenableReports(new ArrayList<TenableReport>());
					combinedMapValue.getTenableReports().add(tenableReport);
					combinedMapValue.setK2Reports(new ArrayList<K2Report>());
					endReport.put(pair, combinedMapValue);
				}
			}

		}
		for (K2Report k2Report : k2Reports) {
			ImmutablePair<String, String> pair = new ImmutablePair<String, String>(k2Report.gethTTPURL(),
					k2Report.getAttackDescription());
			if (endReport.containsKey(pair)) {
				CombinedMapValue combinedMapValue = endReport.get(pair);
				if (combinedMapValue.getK2Reports().size() > 0) {
					combinedMapValue.getK2Reports().add(k2Report);
				} else {
					combinedMapValue.setTenableReports(new ArrayList<TenableReport>());
				}
			} else {
				CombinedMapValue combinedMapValue = new CombinedMapValue();
				combinedMapValue.setTenableReports(new ArrayList<TenableReport>());
				combinedMapValue.setK2Reports(new ArrayList<K2Report>());
				combinedMapValue.getK2Reports().add(k2Report);
				endReport.put(pair, combinedMapValue);
			}

		}
	}

	private static void combineEndReport(Map<ImmutablePair<String, String>, CombinedMapValue> endReport) {

		Set<ImmutablePair<String, String>> set = endReport.keySet();
		Set<ImmutablePair<String, String>> toDelete = new HashSet<ImmutablePair<String, String>>();

		for (ImmutablePair<String, String> immutablePair : set) {
			for (ImmutablePair<String, String> immutablePair2 : set) {
				if (StringUtils.equals(immutablePair.getLeft(), immutablePair2.getLeft())) {
					if (StringUtils.equals(immutablePair.getRight(), "SQL Injection Attack")
							&& !StringUtils.equals(immutablePair2.getRight(), "SQL Injection Attack")
							&& StringUtils.containsIgnoreCase(immutablePair2.getRight(), "SQL Injection")) {
						toDelete.add(immutablePair2);
						endReport.get(immutablePair).getTenableReports()
								.addAll(endReport.get(immutablePair2).getTenableReports());
					} else if (StringUtils.equals(immutablePair.getRight(), "Reflected XSS Attack")
							&& !StringUtils.equals(immutablePair2.getRight(), "Reflected XSS Attack") && StringUtils
									.containsIgnoreCase(immutablePair2.getRight(), "Cross-Site Scripting (XSS)")) {
						toDelete.add(immutablePair2);
						endReport.get(immutablePair).getTenableReports()
								.addAll(endReport.get(immutablePair2).getTenableReports());
					} else if (StringUtils.equals(immutablePair.getRight(), "Remote Code Execution")
							&& !StringUtils.equals(immutablePair2.getRight(), "Remote Code Execution")
							&& StringUtils.containsIgnoreCase(immutablePair2.getRight(),
									"Operating System Command Injection")) {
						toDelete.add(immutablePair2);
						endReport.get(immutablePair).getTenableReports()
								.addAll(endReport.get(immutablePair2).getTenableReports());
					}
				}
			}
		}

		for (ImmutablePair<String, String> immutablePair : toDelete) {
			endReport.remove(immutablePair);
		}
		
		for (ImmutablePair<String, String> immutablePair : endReport.keySet()) {
			if (endReport.get(immutablePair).getK2Reports().size() > 0) {
				endReport.get(immutablePair).setDetectedByK2(true);
			}
			if (endReport.get(immutablePair).getTenableReports().size() > 0) {
				endReport.get(immutablePair).setDetectedByTenable(true);
			}
		}
	}

	private static void prepareSummary(Map<ImmutablePair<String, String>, CombinedMapValue> endReport) {

		sumMap.put("totalCount", endReport.size());
		int commonFindCount = 0;
		int onlyK2Count = 0;
		int onlyTenableCount = 0;

		for (ImmutablePair<String, String> pair : endReport.keySet()) {
			if (endReport.get(pair).getK2Reports().size() > 0 && endReport.get(pair).getTenableReports().size() > 0) {
				commonFindCount++;
			} else if (endReport.get(pair).getK2Reports().size() > 0
					&& endReport.get(pair).getTenableReports().size() == 0) {
				onlyK2Count++;
			} else if (endReport.get(pair).getTenableReports().size() > 0
					&& endReport.get(pair).getK2Reports().size() == 0) {
				onlyTenableCount++;
			}
		}
		sumMap.put("commonFindCount", commonFindCount);
		sumMap.put("onlyK2FindCount", onlyK2Count);
		sumMap.put("onlyTenableFindCount", onlyTenableCount);

	}

	private static void prepareVulnerableApis(Map<ImmutablePair<String, String>, CombinedMapValue> endReport) {
		for (ImmutablePair<String, String> pair : endReport.keySet()) {
			if (vulApis.containsKey(pair.getLeft())) {
				vulApis.get(pair.getLeft()).add(pair.getRight());
			} else {
				vulApis.put(pair.getLeft(), new ArrayList<String>());
				vulApis.get(pair.getLeft()).add(pair.getRight());
			}
		}
	}

	private static void printEndReport(Map<ImmutablePair<String, String>, CombinedMapValue> endReport) {
		System.out.println("\nPRINTING VULNERABILITIES");
		for (ImmutablePair<String, String> pair : endReport.keySet()) {
			System.out.println(pair.getLeft() + " : " + pair.getRight());
		}
		System.out.println("======\n");
	}

	public static void run(List<TenableReport> tenableReports, List<K2Report> k2Reports, String OUTPUT_DIR) {

		prepareEndReport(tenableReports, k2Reports);

		combineEndReport(endReport);

		printEndReport(endReport);

		prepareSummary(endReport);

		prepareVulnerableApis(endReport);

		TenablePDFWriter.write(sumMap, vulApis, endReport, OUTPUT_DIR);
	}

}
