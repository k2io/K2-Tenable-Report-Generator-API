package com.k2cybersecurity.tenable.reportgenerator;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class GetScannedReports {
	private static String tenableUrl = "https://cloud.tenable.com";
	private static String XApiKeys = StringUtils.EMPTY;
	private static String k2Url = "https://www.k2io.net/centralmanager";
	private static String k2CustomerId = StringUtils.EMPTY;
	private static String k2CustomerEmail = StringUtils.EMPTY;
	private static String k2CustomerPassword = StringUtils.EMPTY;
	private static Long startTime;
	private static Long endTime;
	private static String exportedFileName = StringUtils.EMPTY;
	private static final String COOKIES_HEADER = "Set-Cookie";
	private static java.net.CookieManager cookieManager = new java.net.CookieManager();
	private static String K2_REPORT_NAME = "K2-Report.csv";
	private static String TENABLE_REPORT_NAME = "Tenable-Report.csv";
	public static final String ANSI_GREEN = "\u001B[32m";
	public static final String ANSI_RESET = "\u001B[0m";

	private static void tenableScanInfo(String SCAN_ID) {
		String url = tenableUrl + "/scans/" + SCAN_ID;
		try {
			System.out.println("url : -> " + url);
			HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
			httpClient.addRequestProperty("X-ApiKeys", XApiKeys);
			httpClient.addRequestProperty("User-Agent", "Integration/1.0 (K2 Cyber Security; K2-Tenable; 1.0)");
			httpClient.setRequestMethod("GET");
			BufferedReader response = new BufferedReader(new InputStreamReader(httpClient.getInputStream()));
			JSONParser parser = new JSONParser();
			JSONObject json = (JSONObject) parser.parse(response);
			JSONObject info = (JSONObject) json.get("info");
			System.out.println("Tenable Scan info for ID: " + SCAN_ID + "\n" + info.toJSONString());
			System.out.println("Tenable Scan Start Timestamp : " + info.get("scan_start"));
			startTime = (Long) info.get("scan_start") * 1000;
			System.out.println("Tenable Scan End Timestamp : " + info.get("scan_end"));
			endTime = (Long) info.get("scan_end") * 1000;

		} catch (IOException | ParseException e) {
			System.out.println("Error in fetcing tenable scan info");
			System.exit(1);
		}
	}

	private static void tenableExportReport(String SCAN_ID) {
		String url = tenableUrl + "/scans/" + SCAN_ID + "/export?type=web-app";
		try {
			HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
			httpClient.setRequestProperty("Accept", "application/json");
			httpClient.setRequestProperty("content-type", "application/json");
			httpClient.addRequestProperty("X-ApiKeys", XApiKeys);
			httpClient.addRequestProperty("User-Agent", "Integration/1.0 (K2 Cyber Security; K2-Tenable; 1.0)");
			httpClient.setDoOutput(true);
			httpClient.setRequestMethod("POST");

			String body = "{\"format\":\"csv\"}";
			try (OutputStream os = httpClient.getOutputStream()) {
				byte[] input = body.getBytes("utf-8");
				os.write(input, 0, input.length);
			}

			BufferedReader response = new BufferedReader(new InputStreamReader(httpClient.getInputStream()));
			JSONParser parser = new JSONParser();
			JSONObject json = (JSONObject) parser.parse(response);
			System.out.println("Tenable Report Export Response : " + json.toJSONString());
			exportedFileName = (String) json.get("file");
			System.out.println("File name : " + exportedFileName);
		} catch (IOException | ParseException e) {
			System.out.println("Error in exporting temable report");
			System.exit(1);
		}
	}

	private static boolean tenableExportStatus(String SCAN_ID, String exportedFileName) {
		String url = tenableUrl + "/scans/" + SCAN_ID + "/export/" + exportedFileName + "/status?type=web-app";
		try {
			HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
			httpClient.setRequestProperty("Accept", "application/json");
			httpClient.addRequestProperty("X-ApiKeys", XApiKeys);
			httpClient.addRequestProperty("User-Agent", "Integration/1.0 (K2 Cyber Security; K2-Tenable; 1.0)");
			httpClient.setRequestMethod("GET");

			BufferedReader response = new BufferedReader(new InputStreamReader(httpClient.getInputStream()));
			JSONParser parser = new JSONParser();
			JSONObject json = (JSONObject) parser.parse(response);
			System.out.println("Tenable Export Status Response : " + json.toJSONString());
			String status = (String) json.get("status");
			System.out.println("Status : " + status);
			if (StringUtils.equals(status, "ready")) {
				return true;
			} else {
				return false;
			}
		} catch (IOException | ParseException e) {
			e.printStackTrace();
			return false;
		}
	}

	private static void tenableDownloadReport(String SCAN_ID, String OUTPUT_DIR, String exportedFileName) {
		String url = tenableUrl + "/scans/" + SCAN_ID + "/export/" + exportedFileName + "/download?type=web-app";
		try {
			HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
			httpClient.setRequestProperty("Accept", "application/json");
			httpClient.addRequestProperty("X-ApiKeys", XApiKeys);
			httpClient.addRequestProperty("User-Agent", "Integration/1.0 (K2 Cyber Security; K2-Tenable; 1.0)");
			httpClient.setRequestMethod("GET");

			BufferedReader response = new BufferedReader(new InputStreamReader(httpClient.getInputStream()));
			System.out.println("Saving Tenable Report in file : " + OUTPUT_DIR + "/" + TENABLE_REPORT_NAME);
			IOUtils.copy(response, new FileOutputStream(new File(OUTPUT_DIR + "/" + TENABLE_REPORT_NAME)), "utf-8");
			response.close();
		} catch (IOException e) {
			System.out.println("Error in downloading exported report");
			System.exit(1);
		}
	}

	private static void k2Session() {
		String url = k2Url + "/login";
		try {
			HttpsURLConnection httpClient = (HttpsURLConnection) new URL(url).openConnection();
			httpClient.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");
			httpClient.setDoOutput(true);
			httpClient.setRequestMethod("POST");
			String body = "j_username=" + k2CustomerEmail + "&j_password=" + k2CustomerPassword;
			try (OutputStream os = httpClient.getOutputStream()) {
				byte[] input = body.getBytes("utf-8");
				os.write(input, 0, input.length);
			}
			Map<String, List<String>> headerFields = httpClient.getHeaderFields();
			List<String> cookiesHeader = headerFields.get(COOKIES_HEADER);

			if (cookiesHeader != null) {
				for (String cookie : cookiesHeader) {
					cookieManager.getCookieStore().add(null, HttpCookie.parse(cookie).get(0));
				}
			}
			BufferedReader response = new BufferedReader(new InputStreamReader(httpClient.getInputStream()));
			String res = response.readLine();
			System.out.println("K2 Login Response : " + res);
			if (StringUtils.equals(res, "ok")) {
				System.out.println("Logged in successfully, Session created.");
			}
			IOUtils.copy(response, new FileOutputStream(new File("/Users/prateek/Downloads/k2output.csv")), "utf-8");
			response.close();
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Error in session creation for downloading K2 report");
			System.exit(1);
		}
	}

	private static void k2DownloadReport(String OUTPUT_DIR) {
		String url = k2Url + "/api/v1/incident/attack/csv/" + k2CustomerId + "?startTime=" + startTime + "&endTime="
				+ endTime;
		try {
			HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
			httpClient.setRequestMethod("GET");

			if (cookieManager.getCookieStore().getCookies().size() > 0) {
				httpClient.setRequestProperty("Cookie",
						StringUtils.join(cookieManager.getCookieStore().getCookies(), ';'));
			}
			BufferedReader response = new BufferedReader(new InputStreamReader(httpClient.getInputStream()));
			System.out.println("Saving K2 Report in file : " + OUTPUT_DIR + "/" + K2_REPORT_NAME);
			IOUtils.copy(response, new FileOutputStream(new File(OUTPUT_DIR + "/" + K2_REPORT_NAME)), "utf-8");
			response.close();
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Error in downloading K2 report");
			System.exit(1);
		}
	}

	private static void k2FilterReport(String hostIp, String appName, String outputDir) {
		System.out.println("Filtering K2 report for hostIp and appName");
		try {
			File inputFile = new File(outputDir + "/" + K2_REPORT_NAME);
			File tempFile = new File("tempFile.csv");

			BufferedReader reader = new BufferedReader(new FileReader(inputFile));
			BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile));

			String currentLine;
			int skip = 0;
			while ((currentLine = reader.readLine()) != null) {
				if (skip == 0) {
					writer.write(currentLine + System.getProperty("line.separator"));
					skip++;
					continue;
				}
				if (StringUtils.contains(currentLine, hostIp) && StringUtils.contains(currentLine, appName)) {
					writer.write(currentLine + System.getProperty("line.separator"));
				}
			}
			writer.close();
			reader.close();
			tempFile.delete();
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Error in filtering K2 report");
			System.exit(1);
		}

	}

	public static void run(String dastProperties, String k2Properties, String SCAN_ID, String hostIp, String appName,
			String OUTPUT_DIR) {
		try {
			Properties properties = new Properties();
			properties.load(new FileInputStream(new File(dastProperties)));
			tenableUrl = properties.getProperty("tenableUrl");
			XApiKeys = "accessKey=" + properties.getProperty("accessKey") + "; secretKey="
					+ properties.getProperty("secretKey") + ";";

		} catch (IOException e1) {
			System.out.println("DAST Properties files doesn't exist, please provide correct -dastProperties parameter");
			System.exit(1);
		}
		try {
			Properties properties = new Properties();
			properties.load(new FileInputStream(new File(k2Properties)));
			k2Url = properties.getProperty("k2Url");
			k2CustomerId = properties.getProperty("k2CustomerId");
			k2CustomerEmail = properties.getProperty("k2CustomerEmail");
			k2CustomerPassword = properties.getProperty("k2CustomerPassword");
		} catch (IOException e1) {
			System.out.println("K2 Properties files doesn't exist, please provide correct -dastProperties parameter");
			System.exit(1);
		}
		System.out.println("==========================");
		System.out.println(ANSI_GREEN + "STEP 2: " + ANSI_RESET + "Connecting to Tenable");
		System.out.println();
		tenableScanInfo(SCAN_ID);
		tenableExportReport(SCAN_ID);
		if (StringUtils.isNotBlank(exportedFileName)) {
			int retry = 5;
			while (retry-- > 0) {
				if (tenableExportStatus(SCAN_ID, exportedFileName)) {
					tenableDownloadReport(SCAN_ID, OUTPUT_DIR, exportedFileName);
					break;
				}
				try {
					System.out.println("Report not extracted yet, Retrying...");
					TimeUnit.SECONDS.sleep(60);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
			if (retry == 0) {
				System.out.println("Tenable Report not extracted properly, Exiting");
				System.exit(1);
			}
		} else {
			System.out.println("Tenable report not extracted.");
		}
		System.out.println("==========================");
		System.out.println(ANSI_GREEN + "STEP 3: " + ANSI_RESET + "Connecting to K2");
		System.out.println();
		k2Session();
		k2DownloadReport(OUTPUT_DIR);
		k2FilterReport(hostIp, appName, OUTPUT_DIR);
	}

//	public static void main(String[] args) {
//		System.out.println("Working Directory = " + System.getProperty("user.dir"));
//		tenableScanInfo();
//		String exportedFileName = tenableExportReport();
//		System.out.println("sun :" + exportedFileName);
//		if (StringUtils.isNotBlank(exportedFileName) && tenableExportStatus(exportedFileName)) {
//			System.out.println("in if");
//			tenableDownloadReport(exportedFileName);
//		}
//		String ses = k2Session();
//		k2DownloadReport(ses);
//	}

}
