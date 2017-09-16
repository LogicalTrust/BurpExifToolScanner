package burp;

import java.io.PrintWriter;

import net.logicaltrust.ExifToolProcess;
import net.logicaltrust.ExifToolScanner;
import net.logicaltrust.ExtensionInitException;

public class BurpExtender implements IBurpExtender {

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
		try {
			ExifToolProcess exiftoolProcess = new ExifToolProcess();
			ExifToolScanner scanner = new ExifToolScanner(callbacks.getHelpers(), exiftoolProcess, stderr);
			callbacks.registerScannerCheck(scanner);
		} catch (ExtensionInitException e) {
			e.printStackTrace(stderr);
		}
	}

}
