package net.logicaltrust;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

public class ExifToolProcess {

	private final PrintWriter writer;
	private final BufferedReader reader;

	public ExifToolProcess() throws ExtensionInitException {
		try {
			Process process = new ProcessBuilder(new String[] { "exiftool", "-stay_open", "True", "-@", "-" }).start();
			writer = new PrintWriter(process.getOutputStream());
			reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
				@Override
				public void run() {
					process.destroy();
				}
			}));
		} catch (IOException e) {
			throw new ExtensionInitException("Cannot run ExifTool process. Do you have exiftool set in your PATH?", e);
		}
	}

	public BufferedReader getReader() {
		return reader;
	}

	public PrintWriter getWriter() {
		return writer;
	}
	
}
