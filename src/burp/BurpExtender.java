package burp;

import java.io.PrintWriter;

import net.logicaltrust.ExifToolEditorTabFactory;
import net.logicaltrust.ExifToolProcess;
import net.logicaltrust.ExifToolScannerCheck;
import net.logicaltrust.ExtensionInitException;

public class BurpExtender implements IBurpExtender {

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
		try {
			ExifToolProcess exiftoolProcess = new ExifToolProcess(callbacks.getHelpers());
			ExifToolScannerCheck scanner = new ExifToolScannerCheck(callbacks.getHelpers(), exiftoolProcess, stderr);
			callbacks.registerScannerCheck(scanner);
			ExifToolEditorTabFactory tabFactory = new ExifToolEditorTabFactory(callbacks, exiftoolProcess, stderr);
			callbacks.registerMessageEditorTabFactory(tabFactory);
		} catch (ExtensionInitException e) {
			e.printStackTrace(stderr);
		}
	}

}
