package net.logicaltrust;

import java.net.URL;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

public class ExifToolScanIssue implements IScanIssue {

	private URL url;
	private String issueDetail;
	private IHttpRequestResponse[] httpMessages;
	private IHttpService httpService;
	private String issueName;

	public ExifToolScanIssue(URL url, String issueDetail, IHttpRequestResponse[] httpMessages,
			IHttpService httpService, String issueName) {
		super();
		this.url = url;
		this.issueDetail = issueDetail;
		this.httpMessages = httpMessages;
		this.httpService = httpService;
		this.issueName = issueName;
	}

	@Override
	public URL getUrl() {
		return url;
	}

	@Override
	public String getIssueName() {
		return issueName;
	}

	@Override
	public int getIssueType() {
		return 0;
	}

	@Override
	public String getSeverity() {
		return "Information";
	}

	@Override
	public String getConfidence() {
		return "Certain";
	}

	@Override
	public String getIssueBackground() {
		return null;
	}

	@Override
	public String getRemediationBackground() {
		return null;
	}

	@Override
	public String getIssueDetail() {
		return issueDetail;
	}

	@Override
	public String getRemediationDetail() {
		return null;
	}

	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		return httpMessages;
	}

	@Override
	public IHttpService getHttpService() {
		return httpService;
	}

}
