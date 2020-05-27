package com.k2cybersecurity.tenable.reportgenerator;

import java.io.FileNotFoundException;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;

import com.itextpdf.kernel.color.Color;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfPage;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.AreaBreak;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.property.TextAlignment;
import com.itextpdf.layout.property.UnitValue;
import com.k2cybersecurity.k2.models.K2Report;
import com.k2cybersecurity.tenable.models.CombinedMapValue;

public class TenablePDFWriter {

	public static void write(Map<String, Integer> summaryMap, Map<String, List<String>> vulApis,
			Map<ImmutablePair<String, String>, CombinedMapValue> endReport, String OUTPUT_DIR) {

		String filename = OUTPUT_DIR + "/K2-Tenable-Report.pdf";
		System.out.println("Wrinting K2 & Tenable joint PDF report" + filename);
		PdfWriter writer;
		try {
			writer = new PdfWriter(filename);
			PdfDocument pdf = new PdfDocument(writer);
			Document document = new Document(pdf);
			document.add(new Paragraph("K2 & TENABLE JOINT REPORT").setBackgroundColor(Color.GRAY).setBold()
					.setBackgroundColor(Color.DARK_GRAY).setFontColor(Color.WHITE).setBold()
					.setTextAlignment(TextAlignment.CENTER).setFontSize(20f));

			document.add(new Paragraph("Summary").setBackgroundColor(Color.ORANGE).setFontColor(Color.BLACK).setBold()
					.setPadding(3f));

			document.add(new Paragraph("Total Critical/High Risk Vulnerabilities = " + summaryMap.get("totalCount")));
			document.add(new Paragraph("Critical/High Risk Vulnerabilities (Found by Both K2 and Tenable) = "
					+ summaryMap.get("commonFindCount")));
			document.add(new Paragraph("Critical/High Risk Vulnerabilities (Found by Tenable Only) = "
					+ summaryMap.get("onlyTenableFindCount")));
			document.add(new Paragraph(
					"Critical/High Risk Vulnerabilities (Found by K2 Only) = " + summaryMap.get("onlyK2FindCount")));
			document.add(new AreaBreak());

			document.add(new Paragraph("Vulnerable APIs").setBackgroundColor(Color.ORANGE).setFontColor(Color.BLACK)
					.setBold().setPadding(3f));

			Table table = new Table(new float[] { 1, 1 });
			table.setWidth(UnitValue.createPercentValue(100f));

			table.addHeaderCell(new Paragraph("URI").setBold().setFontColor(Color.BLUE));
			table.addHeaderCell(new Paragraph("Vulnerabilities").setBold().setFontColor(Color.BLUE));

			for (String str : vulApis.keySet()) {
				String api = "";
				table.addCell(str);
				for (String s : vulApis.get(str)) {
					api += s + "\n";
				}
				table.addCell(api);
			}
			document.add(table);
			document.add(new AreaBreak());

			for (ImmutablePair<String, String> pair : endReport.keySet()) {
				document.add(new Paragraph("Vulnerability : " + pair.getRight()).setBackgroundColor(Color.ORANGE)
						.setFontColor(Color.BLACK).setBold().setPadding(3f));
				document.add(new Paragraph("Path : " + pair.getLeft()));
				document.add(new Paragraph("Tenable information").setUnderline().setFontColor(Color.BLUE));
				if (endReport.get(pair).getTenableReports().size() == 0) {
					document.add(new Paragraph("Tenable did not detect this vulnerability.")
							.setBackgroundColor(Color.LIGHT_GRAY).setPadding(5f));
				} else {
					String tenableReport = "";
					tenableReport += "Name : " + endReport.get(pair).getTenableReports().get(0).getName();
					tenableReport += "\nFinding ID : " + endReport.get(pair).getTenableReports().get(0).getPluginID();
					tenableReport += "\nRisk : " + endReport.get(pair).getTenableReports().get(0).getRisk();

					if (endReport.get(pair).getTenableReports().get(0).getTenablePluginOutput().getUrl() != null) {
						if (endReport.get(pair).getTenableReports().get(0).getTenablePluginOutput()
								.getDetectionInformation() != null) {
							String di = "";

							for (String str : endReport.get(pair).getTenableReports().get(0).getTenablePluginOutput()
									.getDetectionInformation().keySet()) {
								di += "\n" + str + " : ";
								di += endReport.get(pair).getTenableReports().get(0).getTenablePluginOutput()
										.getDetectionInformation().get(str);
							}
							tenableReport += "\nDetection Information :" + di;
						}
					} else {
						if (StringUtils.isNotBlank(endReport.get(pair).getTenableReports().get(0).getPluginOutput())) {
							tenableReport += "Plugin Output: \n"
									+ endReport.get(pair).getTenableReports().get(0).getPluginOutput();
						}
					}

					if (!StringUtils.isEmpty(
							endReport.get(pair).getTenableReports().get(0).getTenablePluginOutput().getProof())) {
						tenableReport += "\nProof : "
								+ endReport.get(pair).getTenableReports().get(0).getTenablePluginOutput().getProof();
					}
					document.add(new Paragraph(tenableReport).setBackgroundColor(Color.LIGHT_GRAY).setPadding(5f));
				}

				document.add(new Paragraph("K2 information").setUnderline().setFontColor(Color.BLUE));

				if (endReport.get(pair).getK2Reports().size() == 0) {
					String output = "K2 did not detect this vulnerability. It is likely a false positive reported by Tenable. Please view K2 logs to confirm or contact K2 team for support.";

					String addOn = "";

					for (ImmutablePair<String, String> p : endReport.keySet()) {
						if (StringUtils.equals(p.getLeft(), pair.getLeft())
								&& !StringUtils.equals(p.getRight(), pair.getRight())
								&& endReport.get(p).isDetectedByK2()) {
							addOn += "\n- " + p.getRight();
						}
					}
					if (StringUtils.isNotBlank(addOn)) {
						output += "\nHowever, K2 detected following other vulnerabilities for this URL.";
						output += addOn;
					}
					document.add(new Paragraph(output).setBackgroundColor(Color.LIGHT_GRAY).setPadding(5f));
				} else {
					List<K2Report> list = endReport.get(pair).getK2Reports();

					String k2Report = "";
					k2Report += "Name : " + list.get(0).getAttackDescription();
					k2Report += "\nFinding ID : " + list.get(0).getIncidentID();
					k2Report += "\nRisk : High";
					k2Report += "\nFile Name : " + list.get(0).getFileName();
					k2Report += "\nMethod Name : " + list.get(0).getMethodName();
					k2Report += "\nLine Number : " + list.get(0).getLineNumber();
					k2Report += "\nParameters : \n" + list.get(0).getParameterMap();
					k2Report += "\nExecuted Query/Command : " + list.get(0).getExecutedQueryOrCommand();

					document.add(new Paragraph(k2Report).setBackgroundColor(Color.LIGHT_GRAY).setPadding(5f));
				}
				document.add(new AreaBreak());
			}
			PdfPage lastPage = pdf.getLastPage();
			if (lastPage.getContentBytes().length == 0) {
				pdf.removePage(lastPage);
			}
			document.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

}
