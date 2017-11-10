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
		PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
		
		try {
			ExifToolProcess exiftoolProcess = new ExifToolProcess(callbacks.getHelpers(), stdout);
			ExifToolScannerCheck scanner = new ExifToolScannerCheck(callbacks.getHelpers(), exiftoolProcess, stderr);
			ExifToolEditorTabFactory tabFactory = new ExifToolEditorTabFactory(callbacks, exiftoolProcess, stderr);
			ExifToolOptionsManager optionsManager = new ExifToolOptionsManager(callbacks, exiftoolProcess, scanner, tabFactory, stdout);
			callbacks.addSuiteTab(new ExifToolPanel(optionsManager, stderr));
			callbacks.registerExtensionStateListener(exiftoolProcess);
		} catch (ExtensionInitException e) {
			e.printStackTrace(stderr);
		}
	}

}
