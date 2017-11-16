package net.logicaltrust;

import java.io.BufferedReader;
import java.io.File;
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
import burp.IExtensionStateListener;
import burp.IResponseInfo;

public class ExifToolProcess implements IExtensionStateListener {
	
	private volatile Collection<String> typesToIgnore;
	private volatile Collection<String> linesToIgnore;
	
	private static final FileAttribute<Set<PosixFilePermission>> TEMP_FILE_PERMISSIONS = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
	private static final FileAttribute<Set<PosixFilePermission>> TEMP_DIR_PERMISSIONS = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"));

	private final PrintWriter writer;
	private final BufferedReader reader;
	private final IExtensionHelpers helpers;
	private final Path tempDirectory;
	private final SimpleLogger logger;
	private Process process;

	public ExifToolProcess(IExtensionHelpers helpers, SimpleLogger stdout) throws ExtensionInitException {
		this.helpers = helpers;
		this.logger = stdout;
		
		try {
			process = new ProcessBuilder(new String[] { "exiftool", "-stay_open", "True", "-@", "-" }).start();
			writer = new PrintWriter(process.getOutputStream());
			reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			stdout.debug("Process started");
		} catch (IOException e) {
			throw new ExtensionInitException("Cannot run ExifTool process. Do you have exiftool set in your PATH?", e);
		}
		
		try {
			if (isWindows()) {
				tempDirectory = Files.createTempDirectory("burpexiftool");
				setWindowsPermissions(tempDirectory);
			} else {
				tempDirectory = Files.createTempDirectory("burpexiftool", TEMP_DIR_PERMISSIONS);
			}
			tempDirectory.toFile().deleteOnExit();
			stdout.debug("Temp directory " + tempDirectory + " created");
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
	
	public boolean canReadMetadata(byte[] response) {
		IResponseInfo responseInfo = helpers.analyzeResponse(response);
		return isMimeTypeAppropriate(responseInfo);
	}
	
	private List<String> readMetadata(byte[] response, String exifToolParams) throws IOException {
		logger.debug("Reading metadata from response");
		IResponseInfo responseInfo = helpers.analyzeResponse(response);
		if (!isMimeTypeAppropriate(responseInfo)) {
			logger.debug("Inappropriate MIME Type: " + responseInfo.getStatedMimeType() + ", " + responseInfo.getInferredMimeType());
			return Collections.emptyList();
		}
		
		Path tmp = writeToTempFile(responseInfo, response);
		List<String> result;
		synchronized (this) {
			notifyExifTool(tmp, exifToolParams);
			result = readResult();
		}
		logger.debug("Deleting temp file " + tmp);
		Files.deleteIfExists(tmp);
		
		return result;
	}
	
	private boolean isMimeTypeAppropriate(IResponseInfo responseInfo) {
		return !typesToIgnore.contains(responseInfo.getStatedMimeType()) && !typesToIgnore.contains(responseInfo.getInferredMimeType());
	}
	
	private Path writeToTempFile(IResponseInfo responseInfo, byte[] response) throws IOException {
		logger.debug("Creating temp file");
		Path tmp;
		if (isWindows()) {
			tmp = Files.createTempFile(tempDirectory, "file", "");
			setWindowsPermissions(tmp);
		} else {
			 tmp = Files.createTempFile(tempDirectory, "file", "", TEMP_FILE_PERMISSIONS);
		}
		OutputStream tmpOs = Files.newOutputStream(tmp);
		tmpOs.write(response, responseInfo.getBodyOffset(), response.length - responseInfo.getBodyOffset());
		tmpOs.close();
		logger.debug("Temp file " + tmp + " created");
		return tmp;
	}
	
	private void notifyExifTool(Path tmp, String exifToolParams) {
		logger.debug("Notifying exiftool");
		writer.write(exifToolParams);
		writer.write(tmp.toString());
		writer.write("\n-execute\n");
		writer.flush();
		logger.debug("Exiftool notified");
	}

	private List<String> readResult() throws IOException {
		logger.debug("Reading result from exiftool");
		List<String> result = new ArrayList<>();
		String line;
		while ((line = reader.readLine()) != null && logger.debug(line) && !("{ready}".equals(line) || "{ready-}".equals(line))) {
			if (isAppropriateLine(line)) {
				result.add(line);
			}
		}
		logger.debug(result.size() +  " elements read");
		return result;
	}

	private boolean isAppropriateLine(String line) {
		return linesToIgnore.stream().noneMatch((lineToIgnore) -> line.startsWith(lineToIgnore));
	}
	
	private boolean isWindows() {
		return System.getProperty("os.name").toLowerCase().contains("win");
	}
	
	private void setWindowsPermissions(Path path) {
		File file = path.toFile();
		file.setReadable(false, true);
		file.setWritable(true, true);
		file.setExecutable(false);
	}

	@Override
	public void extensionUnloaded() {
		process.destroy();
	}
	
}
