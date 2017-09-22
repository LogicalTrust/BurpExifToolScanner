package net.logicaltrust;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import burp.IExtensionHelpers;
import burp.IResponseInfo;

public class ExifToolProcess {
	
	private volatile Collection<String> typesToIgnore;
	private volatile Collection<String> linesToIgnore;
	
	private static final FileAttribute<Set<PosixFilePermission>> TEMP_FILE_PERMISSIONS = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
	private static final FileAttribute<Set<PosixFilePermission>> TEMP_DIR_PERMISSIONS = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"));

	private final PrintWriter writer;
	private final BufferedReader reader;
	private final IExtensionHelpers helpers;
	private final Path tempDirectory;
	@SuppressWarnings("unused")
	private final PrintWriter stdout;

	public ExifToolProcess(IExtensionHelpers helpers, PrintWriter stdout) throws ExtensionInitException {
		this.helpers = helpers;
		this.stdout = stdout;
		
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
		
		try {
			tempDirectory = Files.createTempDirectory("burpexiftool", TEMP_DIR_PERMISSIONS);
			tempDirectory.toFile().deleteOnExit();
		} catch (IOException e) {
			throw new ExtensionInitException("Cannot create temporary directory", e);
		}
	}
	
	public void setTypesToIgnore(Collection<String> typesToIgnore) {
		this.typesToIgnore = typesToIgnore;
	}
	
	public void setLinesToIgnore(Collection<String> linesToIgnore) {
		this.linesToIgnore = linesToIgnore.stream().map(line -> line + ":").collect(Collectors.toSet());
	}
	
	public List<String> readMetadataHtml(byte[] response) throws IOException {
		return readMetadata(response, "-m\n-S\n-E\n-sort\n");
	}
	
	public List<String> readMetadata(byte[] response) throws IOException {
		return readMetadata(response, "-m\n-S\n-sort\n");
	}
	
	private List<String> readMetadata(byte[] response, String exifToolParams) throws IOException {
		IResponseInfo responseInfo = helpers.analyzeResponse(response);
		if (typesToIgnore.contains(responseInfo.getStatedMimeType()) || typesToIgnore.contains(responseInfo.getInferredMimeType())) {
			return Collections.emptyList();
		}
		
		Path tmp = writeToTempFile(responseInfo, response);
		List<String> result;
		synchronized (this) {
			notifyExifTool(tmp, exifToolParams);
			result = readResult();
		}
		Files.deleteIfExists(tmp);
		
		return result;
	}
	
	private Path writeToTempFile(IResponseInfo responseInfo, byte[] response) throws IOException {
		Path tmp = Files.createTempFile(tempDirectory, "file", "", TEMP_FILE_PERMISSIONS);
		OutputStream tmpOs = Files.newOutputStream(tmp);
		tmpOs.write(response, responseInfo.getBodyOffset(), response.length - responseInfo.getBodyOffset());
		tmpOs.close();
		return tmp;
	}
	
	private void notifyExifTool(Path tmp, String exifToolParams) {
		writer.write(exifToolParams);
		writer.write(tmp.toString());
		writer.write("\n-execute\n");
		writer.flush();
	}

	private List<String> readResult() throws IOException {
		List<String> result = new ArrayList<>();
		String line;
		while ((line = reader.readLine()) != null && !"{ready}".equals(line)) {
			if (isAppropriateLine(line)) {
				result.add(line);
			}
		}
		return result;
	}

	private boolean isAppropriateLine(String line) {
		return linesToIgnore.stream().noneMatch((lineToIgnore) -> line.startsWith(lineToIgnore));
	}
	
}
