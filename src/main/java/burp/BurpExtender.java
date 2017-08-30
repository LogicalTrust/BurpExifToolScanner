package burp;

import net.logicaltrust.ExifToolScanner;

public class BurpExtender implements IBurpExtender {

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.registerScannerCheck(new ExifToolScanner(callbacks.getHelpers()));
	}

}
