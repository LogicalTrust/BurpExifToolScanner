package net.logicaltrust.gui;

class ModifyCellUndoAction implements UndoAction {

	private final Object valueAt;
	private final int row;
	private final int column;

	public ModifyCellUndoAction(Object valueAt, int row, int column) {
		this.valueAt = valueAt;
		this.row = row;
		this.column = column;
	}

	@Override
	public void undo(ExifToolTableModel exifToolTableModel) {
		exifToolTableModel.undoModifyCell(valueAt, row, column);
	}

}
