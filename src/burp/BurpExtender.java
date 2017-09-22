package burp;

import java.io.PrintWriter;

import net.logicaltrust.ExifToolEditorTabFactory;
import net.logicaltrust.ExifToolOptionsManager;
import net.logicaltrust.ExifToolProcess;
import net.logicaltrust.ExifToolScannerCheck;
import net.logicaltrust.ExtensionInitException;
import net.logicaltrust.gui.ExifToolPanel;

public class BurpExtender implements IBurpExtender {

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		
		PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
		try {
			ExifToolProcess exiftoolProcess = new ExifToolProcess(callbacks.getHelpers());
			ExifToolScannerCheck scanner = new ExifToolScannerCheck(callbacks.getHelpers(), exiftoolProcess, stderr);
			ExifToolEditorTabFactory tabFactory = new ExifToolEditorTabFactory(callbacks, exiftoolProcess, stderr);
			ExifToolOptionsManager optionsManager = new ExifToolOptionsManager(callbacks, exiftoolProcess, scanner, tabFactory);
			callbacks.addSuiteTab(new ExifToolPanel(optionsManager));
		} catch (ExtensionInitException e) {
			e.printStackTrace(stderr);
		}
	}

}
