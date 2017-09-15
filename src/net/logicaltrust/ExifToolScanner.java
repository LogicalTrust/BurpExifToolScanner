package net.logicaltrust;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.List;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;

public class ExifToolScanner implements IScannerCheck {

	private static final List<String> TYPES_TO_IGNORE = Arrays.asList("HTML", "JSON", "script", "CSS");
	private static final String FILETYPE_KEY = "FileType: ";
	private static final List<String> RESULT_LINES_TO_IGNORE = Arrays.asList("ExifToolVersion:", "Error:", "Directory:", "FileAccessDate:", "FileInodeChangeDate:", "FileModifyDate:", "FileName:", "FilePermissions:", "FileSize");

	private final IExtensionHelpers helpers;
	private OutputStream outputStream;
	private BufferedReader reader;

	public ExifToolScanner(IExtensionHelpers helpers) {
		this.helpers = helpers;
		try {
			Process process = new ProcessBuilder(new String[] { "exiftool", "-stay_open", "True", "-@", "-" }).start();
			outputStream = process.getOutputStream();
			reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		IResponseInfo responseInfo = helpers.analyzeResponse(baseRequestResponse.getResponse());
		List<IScanIssue> issues = null;
		if (!TYPES_TO_IGNORE.contains(responseInfo.getStatedMimeType()) 
				&& !TYPES_TO_IGNORE.contains(responseInfo.getInferredMimeType())) {
			try {
				issues = exiftoolScan(baseRequestResponse, responseInfo);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return issues;
	}
	
	private boolean isLineToIgnore(String line) {
		for (String lineToIgnore : RESULT_LINES_TO_IGNORE) {
			if (line.startsWith(lineToIgnore)) {
				return true;
			}
		}
		return false;
	}
	
	private List<IScanIssue> exiftoolScan(IHttpRequestResponse baseRequestResponse, IResponseInfo responseInfo) throws IOException {
		Path tmp = Files.createTempFile("brpexiftool", "", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
		OutputStream tmpOs = Files.newOutputStream(tmp);
		tmpOs.write(baseRequestResponse.getResponse(), responseInfo.getBodyOffset(), baseRequestResponse.getResponse().length - responseInfo.getBodyOffset());
		tmpOs.close();
		
		outputStream.write("-m\n-S\n-E\n-sort\n".getBytes(StandardCharsets.UTF_8));
		outputStream.write(tmp.toString().getBytes(StandardCharsets.UTF_8));
		outputStream.write("\n-execute\n".getBytes(StandardCharsets.UTF_8));
		outputStream.flush();
		
		StringBuilder details = new StringBuilder();
		String line;
		String filetype = "";
		while ((line = reader.readLine()) != null && !"{ready}".equals(line)) {
			if (!isLineToIgnore(line)) {
				details.append("<li>").append(line).append("</li>");
				if (line.startsWith(FILETYPE_KEY)) {
					filetype = " in " + line.substring(FILETYPE_KEY.length());
				}
			}
		}
		
		Files.deleteIfExists(tmp);
		
		if (details.length() > 0) {
			details.insert(0, "<ul>").append("</ul>");
			URL url = helpers.analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest()).getUrl();
			ExifToolScanIssue i = new ExifToolScanIssue(url, 
					details.toString(), 
					new IHttpRequestResponse[] { baseRequestResponse }, 
					baseRequestResponse.getHttpService(),
					"Metadata" + filetype + " (ExifTool)");
			return Arrays.asList(i);
		}
		
		return null;
	}
	
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		return existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()) ? -1 : 0;
	}

}
