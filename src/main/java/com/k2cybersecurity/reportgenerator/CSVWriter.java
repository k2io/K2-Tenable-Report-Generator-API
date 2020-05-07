package com.k2cybersecurity.reportgenerator;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import com.k2cybersecurity.tenable.models.TenableReport;

public class CSVWriter {

	public static void write(List<TenableReport> tenableReports) {
		try {
			FileWriter out = new FileWriter(new File("/Users/prateek/Downloads/Final.csv"));
			CSVPrinter printer = new CSVPrinter(out,
					CSVFormat.DEFAULT.withHeader("Plugin ID", "CVE", "CVSS", "Risk", "Host", "Protocol", "Port", "Name",
							"Synopsis", "Description", "Solution", "See Also", "Plugin Output", "K2 Output"));

			for (TenableReport tenableReport : tenableReports) {
				List<String> record = new ArrayList<String>();
				record.add(tenableReport.getPluginID());
				record.add(tenableReport.getcVE());
				record.add(tenableReport.getcVSS());
				record.add(tenableReport.getRisk());
				record.add(tenableReport.getHost());
				record.add(tenableReport.getProtocol());
				record.add(tenableReport.getPort());
				record.add(tenableReport.getName());
				record.add(tenableReport.getSynopsis());
				record.add(tenableReport.getDescription());
				record.add(tenableReport.getSolution());
				record.add(tenableReport.getSeeAlso());
				record.add(tenableReport.getPluginOutput());
				record.add(tenableReport.getK2output());
				printer.printRecord(record);
			}
			printer.close(true);
			out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
