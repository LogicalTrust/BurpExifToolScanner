package net.logicaltrust.gui;

import java.util.List;

public class ReplaceAllUndoAction implements UndoAction {

	private final List<Object> oldValues;

	public ReplaceAllUndoAction(List<Object> oldValues) {
		this.oldValues = oldValues;
	}

	@Override
	public void undo(ExifToolTableModel exifToolTableModel) {
		exifToolTableModel.replaceAllUndo(oldValues);
	}

}
