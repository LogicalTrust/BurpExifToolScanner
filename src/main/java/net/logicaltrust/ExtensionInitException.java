package net.logicaltrust;

public class ExtensionInitException extends Exception {

	private static final long serialVersionUID = 1L;

	public ExtensionInitException(String msg) {
		super(msg);
	}
	
	public ExtensionInitException(String msg, Exception e) {
		super(msg, e);
	}
	
}
