"""PySide6 dialog for managing user middleware scripts."""

from __future__ import annotations

import ast
import os
import shutil
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

from middleware import middleware_directory, read_middleware_config, write_middleware_config
from middleware_examples import EXAMPLES


_NEW_SCRIPT = '''"""Describe what this middleware changes."""


def patch(event):
    # Return the event to forward it, a changed event to rewrite it,
    # or None to block it.
    return event
'''


def _validate_source(source: str, filename: str) -> str | None:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return f"Syntax error on line {exc.lineno}: {exc.msg}"
    functions = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("_")
    ]
    if len(functions) != 1:
        return "A middleware must define exactly one public function."
    if any(isinstance(node, ast.AsyncFunctionDef) and node.name == functions[0] for node in tree.body):
        return "The middleware function must be synchronous, not async."
    return None


def _write_source(path: Path, source: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(source, encoding="utf-8")
    os.replace(temporary, path)


class MiddlewareEditorDialog(QDialog):
    def __init__(self, path: Path, parent=None):
        super().__init__(parent)
        self.path = path
        self.setWindowTitle(f"Edit middleware — {path.name}")
        self.resize(800, 600)

        self.editor = QPlainTextEdit(self)
        self.editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.editor.setPlainText(path.read_text(encoding="utf-8"))

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel, self)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.editor, 1)
        layout.addWidget(buttons)

    def _save(self):
        source = self.editor.toPlainText()
        error = _validate_source(source, self.path.name)
        if error:
            QMessageBox.warning(self, "Invalid middleware", error)
            return
        try:
            _write_source(self.path, source)
        except OSError as exc:
            QMessageBox.critical(self, "Could not save middleware", str(exc))
            return
        self.accept()


class MiddlewareManagerDialog(QDialog):
    def __init__(self, parent=None, directory: Path | None = None):
        super().__init__(parent)
        self.directory = directory or middleware_directory()
        self.setWindowTitle("Manage middlewares")
        self.resize(720, 500)

        description = QLabel(
            "Checked scripts are active. They run from top to bottom and reload "
            "automatically after changes.",
            self,
        )
        description.setWordWrap(True)
        self.location = QLabel(str(self.directory), self)
        self.location.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.list = QListWidget(self)
        self.list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.list.setDragDropMode(QAbstractItemView.InternalMove)
        self.list.itemChanged.connect(self._save_config)
        self.list.model().rowsMoved.connect(lambda *_: self._save_config())
        self.list.itemDoubleClicked.connect(lambda *_: self._edit())

        add_button = QPushButton("New", self)
        example_button = QPushButton("Add example…", self)
        import_button = QPushButton("Import…", self)
        edit_button = QPushButton("Edit", self)
        delete_button = QPushButton("Delete", self)
        up_button = QPushButton("Move up", self)
        down_button = QPushButton("Move down", self)
        add_button.clicked.connect(self._create)
        example_button.clicked.connect(self._add_example)
        import_button.clicked.connect(self._import)
        edit_button.clicked.connect(self._edit)
        delete_button.clicked.connect(self._delete)
        up_button.clicked.connect(lambda: self._move(-1))
        down_button.clicked.connect(lambda: self._move(1))

        controls = QVBoxLayout()
        for button in (add_button, example_button, import_button, edit_button, delete_button, up_button, down_button):
            controls.addWidget(button)
        controls.addStretch(1)

        content = QHBoxLayout()
        content.addWidget(self.list, 1)
        content.addLayout(controls)

        buttons = QDialogButtonBox(QDialogButtonBox.Close, self)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(description)
        layout.addWidget(self.location)
        layout.addLayout(content, 1)
        layout.addWidget(buttons)

        self._refresh()

    def _refresh(self, select_name: str | None = None):
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            config = read_middleware_config(self.directory)
            paths = {path.name: path for path in self.directory.glob("*.py") if not path.name.startswith("_")}
        except OSError as exc:
            QMessageBox.critical(self, "Cannot access middleware directory", str(exc))
            return
        names = [name for name in config["order"] if name in paths]
        names.extend(sorted(set(paths) - set(names)))
        disabled = set(config["disabled"])
        self.list.blockSignals(True)
        self.list.clear()
        for name in names:
            item = QListWidgetItem(name)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable | Qt.ItemIsDragEnabled)
            item.setCheckState(Qt.Unchecked if name in disabled else Qt.Checked)
            item.setToolTip(str(paths[name]))
            self.list.addItem(item)
            if name == select_name:
                self.list.setCurrentItem(item)
        self.list.blockSignals(False)
        self._save_config()

    def _items(self):
        return [self.list.item(row) for row in range(self.list.count())]

    def _save_config(self, *_):
        items = self._items()
        try:
            write_middleware_config(
                self.directory,
                [item.text() for item in items],
                [item.text() for item in items if item.checkState() != Qt.Checked],
            )
        except OSError as exc:
            QMessageBox.critical(self, "Could not save middleware settings", str(exc))

    def _selected_path(self) -> Path | None:
        item = self.list.currentItem()
        return self.directory / item.text() if item is not None else None

    def _create(self):
        name, accepted = QInputDialog.getText(self, "New middleware", "File name:", text="my_middleware.py")
        if not accepted:
            return
        name = name.strip()
        if not name.lower().endswith(".py"):
            name += ".py"
        if Path(name).name != name or name.startswith("_") or not name[:-3].replace("_", "a").isalnum():
            QMessageBox.warning(self, "Invalid file name", "Use letters, numbers, and underscores in a .py file name.")
            return
        path = self.directory / name
        if path.exists():
            QMessageBox.warning(self, "Already exists", f"{name} already exists.")
            return
        try:
            _write_source(path, _NEW_SCRIPT)
        except OSError as exc:
            QMessageBox.critical(self, "Could not create middleware", str(exc))
            return
        self._refresh(name)
        self._edit()

    def _import(self):
        source_name, _ = QFileDialog.getOpenFileName(self, "Import middleware", "", "Python files (*.py)")
        if not source_name:
            return
        source = Path(source_name)
        try:
            text = source.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            QMessageBox.critical(self, "Could not read middleware", str(exc))
            return
        error = _validate_source(text, source.name)
        if error:
            QMessageBox.warning(self, "Invalid middleware", error)
            return
        target = self.directory / source.name
        if target.exists() and QMessageBox.question(
            self, "Replace middleware?", f"{source.name} already exists. Replace it?"
        ) != QMessageBox.Yes:
            return
        try:
            shutil.copy2(source, target)
        except OSError as exc:
            QMessageBox.critical(self, "Could not import middleware", str(exc))
            return
        self._refresh(target.name)

    def _add_example(self):
        label, accepted = QInputDialog.getItem(
            self, "Add example middleware", "Template:", list(EXAMPLES), editable=False
        )
        if not accepted:
            return
        filename, source = EXAMPLES[label]
        target = self.directory / filename
        if target.exists() and QMessageBox.question(
            self, "Replace middleware?", f"{filename} already exists. Replace it?"
        ) != QMessageBox.Yes:
            return
        try:
            _write_source(target, source)
        except OSError as exc:
            QMessageBox.critical(self, "Could not add example", str(exc))
            return
        self._refresh(filename)
        self._edit()

    def _edit(self):
        path = self._selected_path()
        if path is None:
            return
        try:
            dialog = MiddlewareEditorDialog(path, self)
        except (OSError, UnicodeError) as exc:
            QMessageBox.critical(self, "Could not open middleware", str(exc))
            return
        dialog.exec()

    def _delete(self):
        path = self._selected_path()
        if path is None:
            return
        if QMessageBox.question(
            self, "Delete middleware?", f"Permanently delete {path.name}?"
        ) != QMessageBox.Yes:
            return
        try:
            path.unlink()
        except OSError as exc:
            QMessageBox.critical(self, "Could not delete middleware", str(exc))
            return
        self._refresh()

    def _move(self, offset: int):
        row = self.list.currentRow()
        target = row + offset
        if row < 0 or target < 0 or target >= self.list.count():
            return
        item = self.list.takeItem(row)
        self.list.insertItem(target, item)
        self.list.setCurrentRow(target)
        self._save_config()
