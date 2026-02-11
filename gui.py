import json
import sys
import threading
from dataclasses import dataclass, field

import msgpack
from PySide6.QtCore import (
    QAbstractTableModel,
    QDateTime,
    QModelIndex,
    QObject,
    Qt,
    Signal,
    QTimer,
)
from PySide6.QtGui import QBrush, QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QSplitter,
    QTabWidget,
    QTableView,
    QToolBar,
    QVBoxLayout,
    QWidget,
    QMessageBox,
)

_gui_lock = threading.Lock()
_gui_app = None
_gui_source = None
_pending_events = []
_command_handlers = []


@dataclass
class NetEvent:
    id: int = 0
    time: QDateTime = field(default_factory=QDateTime)
    direction: str = ""
    event_type: str = ""
    name: str = ""
    payload_utf8: bytes = b""
    raw_bytes: bytes = b""
    status: str = ""
    use_raw_bytes: bool = False


class EventModel(QAbstractTableModel):
    TimeCol = 0
    DirCol = 1
    TypeCol = 2
    NameCol = 3
    SizeCol = 4
    StatusCol = 5
    ColumnCount = 6

    def __init__(self, parent=None):
        super().__init__(parent)
        self._events = []
        self._next_id = 1
        self._id_to_row = {}

    def rowCount(self, parent=QModelIndex()):
        if parent.isValid():
            return 0
        return len(self._events)

    def columnCount(self, parent=QModelIndex()):
        if parent.isValid():
            return 0
        return self.ColumnCount

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        if row < 0 or row >= len(self._events):
            return None
        ev = self._events[row]

        if role == Qt.DisplayRole:
            if col == self.TimeCol:
                return ev.time.toString("HH:mm:ss.zzz")
            if col == self.DirCol:
                return ev.direction
            if col == self.TypeCol:
                return ev.event_type
            if col == self.NameCol:
                return ev.name
            if col == self.SizeCol:
                return str(len(ev.payload_utf8 or b""))
            if col == self.StatusCol:
                return ev.status
            return None

        if role == Qt.ToolTipRole:
            if col == self.NameCol:
                return ev.name
            if col == self.TypeCol:
                return ev.event_type
            if col == self.StatusCol:
                return ev.status
            if col == self.SizeCol:
                return f"{len(ev.payload_utf8 or b'')} bytes"

        if role == Qt.FontRole and col == self.DirCol:
            font = QFont()
            font.setBold(True)
            return font

        if role == Qt.ForegroundRole:
            if col == self.DirCol:
                if ev.direction == "IN":
                    return QBrush(Qt.darkGreen)
                if ev.direction == "OUT":
                    return QBrush(Qt.darkBlue)
            if col == self.StatusCol:
                if "error" in (ev.status or "").lower():
                    return QBrush(Qt.darkRed)

        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation != Qt.Horizontal or role != Qt.DisplayRole:
            return None
        if section == self.TimeCol:
            return "Time"
        if section == self.DirCol:
            return "Dir"
        if section == self.TypeCol:
            return "Type"
        if section == self.NameCol:
            return "Name"
        if section == self.SizeCol:
            return "Size"
        if section == self.StatusCol:
            return "Status"
        return None

    def flags(self, index):
        if not index.isValid():
            return Qt.NoItemFlags
        return Qt.ItemIsSelectable | Qt.ItemIsEnabled

    def add_event(self, ev: NetEvent):
        ev.id = self._next_id
        self._next_id += 1
        if not ev.time.isValid():
            ev.time = QDateTime.currentDateTime()

        row = len(self._events)
        self.beginInsertRows(QModelIndex(), row, row)
        self._events.append(ev)
        self._id_to_row[ev.id] = row
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self._events = []
        self._next_id = 1
        self._id_to_row = {}
        self.endResetModel()

    def event_at_row(self, row: int):
        if row < 0 or row >= len(self._events):
            return None
        return self._events[row]

    def row_for_id(self, ev_id: int):
        return self._id_to_row.get(ev_id, -1)


def _payload_to_utf8(value):
    if value is None:
        return b""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":")).encode("utf-8")
    wrapper = {"value": value}
    return json.dumps(wrapper, separators=(",", ":")).encode("utf-8")


def _safe_json(value):
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _hex_to_bytes(hex_text: str):
    if not hex_text:
        return b""
    cleaned = hex_text.replace(" ", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def _bytes_to_hex(data: bytes) -> str:
    if not data:
        return ""
    return " ".join(f"{b:02x}" for b in data)


def _payload_text_to_value(text: str):
    if text is None:
        return None
    cleaned = text.strip()
    if not cleaned:
        return None
    try:
        return json.loads(cleaned)
    except Exception:
        return text


def _value_to_payload_text(value) -> str:
    try:
        return json.dumps(value, separators=(",", ":"))
    except TypeError:
        return str(value)


class InProcessEventSource(QObject):
    eventCaptured = Signal(NetEvent)
    commandIssued = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)

    def start(self):
        return True

    def send_command(self, obj: dict):
        self.commandIssued.emit(obj)

    def inject_event(self, ev: NetEvent):
        self.eventCaptured.emit(ev)


class EditDialog(QDialog):
    sendRequested = Signal(NetEvent)

    def __init__(self, ev: NetEvent, parent=None):
        super().__init__(parent)
        self._original = ev
        self.setWindowTitle("Edit & Send")
        self.setModal(True)
        self.resize(650, 420)

        self._name = QLineEdit(ev.name, self)
        self._type = QComboBox(self)
        self._type.addItems(["msgServerEvent", "msgNetEvent", "msgNetGameEventV2"])
        self._type.setCurrentText(ev.event_type or "msgServerEvent")
        self._dir = QComboBox(self)
        self._dir.addItems(["IN", "OUT"])
        self._dir.setCurrentText(ev.direction if ev.direction else "OUT")

        self._payload = QPlainTextEdit(self)
        try:
            payload_text = (ev.payload_utf8 or b"").decode("utf-8")
        except UnicodeDecodeError:
            payload_text = (ev.payload_utf8 or b"").decode("utf-8", errors="replace")
        self._original_payload_text = payload_text
        self._payload.setPlainText(payload_text)
        self._payload.setPlaceholderText("Payload (JSON)...")

        self._raw = QPlainTextEdit(self)
        self._raw.setPlainText(_bytes_to_hex(ev.raw_bytes or b""))
        self._raw.setPlaceholderText("Raw bytes (hex)...")

        self._tabs = QTabWidget(self)
        self._tabs.addTab(self._payload, "Payload")
        self._tabs.addTab(self._raw, "Raw")
        self._tab_guard = False
        self._tabs.currentChanged.connect(self._on_tab_changed)

        form = QFormLayout()
        form.addRow("Event type:", self._type)
        form.addRow("Name:", self._name)
        form.addRow("Direction:", self._dir)

        buttons = QDialogButtonBox(self)
        send_btn = buttons.addButton("Send", QDialogButtonBox.AcceptRole)
        buttons.addButton(QDialogButtonBox.Cancel)
        buttons.rejected.connect(self.reject)
        send_btn.clicked.connect(self._on_send)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self._tabs, 1)
        layout.addWidget(buttons)

    def edited_event(self):
        use_raw = self._tabs.currentIndex() == 1
        payload_text = self._payload.toPlainText()
        raw_bytes = _hex_to_bytes(self._raw.toPlainText())
        if not use_raw:
            if (
                payload_text == self._original_payload_text
                and self._original.raw_bytes
            ):
                use_raw = True
                raw_bytes = self._original.raw_bytes
            else:
                if self._type.currentText() != "msgNetGameEventV2":
                    try:
                        value = _payload_text_to_value(payload_text)
                        raw_bytes = msgpack.packb(value, use_bin_type=True, strict_types=True)
                    except Exception:
                        raw_bytes = b""
                else:
                    raw_bytes = _hex_to_bytes(payload_text)
                    if raw_bytes is None:
                        raw_bytes = b""
                    use_raw = True
        ev = NetEvent(
            id=self._original.id,
            time=self._original.time,
            direction=self._dir.currentText(),
            event_type=self._type.currentText(),
            name=self._name.text(),
            payload_utf8=payload_text.encode("utf-8"),
            raw_bytes=raw_bytes,
            status=self._original.status,
            use_raw_bytes=use_raw,
        )
        return ev

    def _on_send(self):
        ev = self.edited_event()
        self.sendRequested.emit(ev)
        self.accept()

    def _on_tab_changed(self, index: int):
        if self._tab_guard:
            return
        if self._type.currentText() == "msgNetGameEventV2":
            if index == 1:
                payload_text = self._payload.toPlainText()
                raw_bytes = _hex_to_bytes(payload_text)
                if payload_text.strip() and raw_bytes == b"":
                    return
                if payload_text.strip():
                    self._raw.setPlainText(_bytes_to_hex(raw_bytes))
            else:
                raw_bytes = _hex_to_bytes(self._raw.toPlainText())
                if self._raw.toPlainText().strip() and raw_bytes == b"":
                    return
                if self._raw.toPlainText().strip():
                    self._payload.setPlainText(_bytes_to_hex(raw_bytes))
            return
        if index == 1:
            try:
                value = _payload_text_to_value(self._payload.toPlainText())
                packed = msgpack.packb(value, use_bin_type=True, strict_types=True)
            except Exception as exc:
                self._warn_conversion_failed(f"Failed to pack payload to msgpack: {exc}")
                self._set_tab(0)
                return
            self._raw.setPlainText(_bytes_to_hex(packed))
            return

        try:
            raw_bytes = _hex_to_bytes(self._raw.toPlainText())
            unpacked = msgpack.unpackb(raw_bytes, raw=False)
        except Exception as exc:
            self._warn_conversion_failed(
                "Raw bytes are not a valid msgpack object; staying on Raw tab."
            )
            self._set_tab(1)
            return
        self._payload.setPlainText(_value_to_payload_text(unpacked))

    def _set_tab(self, index: int):
        self._tab_guard = True
        try:
            self._tabs.setCurrentIndex(index)
        finally:
            self._tab_guard = False

    def _warn_conversion_failed(self, message: str):
        QMessageBox.warning(self, "Conversion failed", message)


class MainWindow(QMainWindow):
    def __init__(self, parent=None, event_source=None):
        super().__init__(parent)
        self.setWindowTitle("Event Inspector")
        self.resize(1200, 700)

        self._model = EventModel(self)
        self._sniffer_source = event_source or InProcessEventSource(self)
        self._open_dialogs = []
        self._filter_needle_lower = ""

        toolbar = QToolBar("Main", self)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        toolbar.addWidget(QLabel("Filter:", self))

        self._filter = QLineEdit(self)
        self._filter.setPlaceholderText("name or payload...")
        self._filter.setClearButtonEnabled(True)
        self._filter.setMaximumWidth(380)
        toolbar.addWidget(self._filter)

        clear_action = toolbar.addAction("Clear")
        clear_action.triggered.connect(self._on_clear)
        new_action = toolbar.addAction("New")
        new_action.triggered.connect(self._on_new_event)
        edit_selected_action = toolbar.addAction("Edit Selected")
        edit_selected_action.triggered.connect(self._on_edit_selected)
        resend_selected_action = toolbar.addAction("Resend Selected")
        resend_selected_action.triggered.connect(self._on_resend_selected)
        self._autoscroll_action = toolbar.addAction("Auto-scroll")
        self._autoscroll_action.setCheckable(True)
        self._autoscroll_action.setChecked(True)
        self._filter.textChanged.connect(self._on_filter_text_changed)

        self._table = QTableView(self)
        self._table.setModel(self._model)
        self._table.setSelectionBehavior(QTableView.SelectRows)
        self._table.setSelectionMode(QTableView.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableView.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setColumnWidth(EventModel.TimeCol, 115)
        self._table.setColumnWidth(EventModel.DirCol, 55)
        self._table.setColumnWidth(EventModel.TypeCol, 150)
        self._table.setColumnWidth(EventModel.NameCol, 220)
        self._table.setColumnWidth(EventModel.SizeCol, 70)
        self._table.setColumnWidth(EventModel.StatusCol, 110)

        details = QWidget(self)
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(8, 8, 8, 8)

        self._summary = QLabel("Select an event to see details.", details)
        self._summary.setWordWrap(True)

        tabs = QTabWidget(details)
        self._payload_view = QPlainTextEdit(details)
        self._payload_view.setReadOnly(True)
        self._payload_view.setPlaceholderText("Payload...")

        self._raw_view = QPlainTextEdit(details)
        self._raw_view.setReadOnly(True)
        self._raw_view.setPlaceholderText("Raw bytes (hex)...")

        tabs.addTab(self._payload_view, "Payload")
        tabs.addTab(self._raw_view, "Raw")

        details_layout.addWidget(self._summary)
        details_layout.addWidget(tabs, 1)

        split = QSplitter(Qt.Horizontal, self)
        split.addWidget(self._table)
        split.addWidget(details)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        self.setCentralWidget(split)

        self._sniffer_source.eventCaptured.connect(self._on_event_captured)
        self._table.selectionModel().selectionChanged.connect(self._on_selection_changed)

        self._sniffer_source.start()

    def _on_clear(self):
        self._model.clear()
        self._summary.setText("Select an event to see details.")
        self._payload_view.clear()
        self._raw_view.clear()

    def _on_event_captured(self, ev: NetEvent):
        row_before = self._model.rowCount()
        self._model.add_event(ev)
        row = row_before
        self._table.setRowHidden(row, not self._event_matches_filter(ev))
        if self._autoscroll_action.isChecked():
            self._table.scrollToBottom()

    def _on_selection_changed(self):
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            self._summary.setText("Select an event to see details.")
            self._payload_view.clear()
            self._raw_view.clear()
            return
        self._update_details_for_row(rows[0].row())

    def _update_details_for_row(self, row: int):
        ev = self._model.event_at_row(row)
        if ev is None:
            return
        self._summary.setText(
            f"[{ev.time.toString('yyyy-MM-dd HH:mm:ss.zzz')}] "
            f"{ev.direction}  {ev.event_type}  {ev.name}  ({len(ev.payload_utf8 or b'')} bytes)\n"
            f"status: {ev.status}"
        )
        try:
            self._payload_view.setPlainText((ev.payload_utf8 or b"").decode("utf-8"))
        except UnicodeDecodeError:
            self._payload_view.setPlainText((ev.payload_utf8 or b"").decode("utf-8", errors="replace"))

        if not ev.raw_bytes:
            self._raw_view.setPlainText("")
        else:
            self._raw_view.setPlainText(" ".join(f"{b:02x}" for b in ev.raw_bytes))

    def _on_filter_text_changed(self, text: str):
        self._filter_needle_lower = text.strip().lower()
        for row in range(self._model.rowCount()):
            ev = self._model.event_at_row(row)
            if ev is None:
                continue
            self._table.setRowHidden(row, not self._event_matches_filter(ev))

    def _event_matches_filter(self, ev: NetEvent) -> bool:
        if not self._filter_needle_lower:
            return True
        if self._filter_needle_lower in (ev.name or "").lower():
            return True
        payload_text = ""
        if ev.payload_utf8:
            try:
                payload_text = ev.payload_utf8.decode("utf-8")
            except UnicodeDecodeError:
                payload_text = ev.payload_utf8.decode("utf-8", errors="replace")
        return self._filter_needle_lower in payload_text.lower()

    def _on_edit_event(self, ev_id: int):
        row = self._model.row_for_id(ev_id)
        ev = self._model.event_at_row(row)
        if ev is None:
            return
        self._open_edit_dialog(ev)

    def _selected_event_id(self):
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        ev = self._model.event_at_row(rows[0].row())
        if ev is None:
            return None
        return ev.id

    def _on_edit_selected(self):
        ev_id = self._selected_event_id()
        if ev_id is None:
            return
        self._on_edit_event(ev_id)

    def _on_new_event(self):
        ev = NetEvent(
            time=QDateTime.currentDateTime(),
            direction="OUT",
            event_type="msgServerEvent",
            name="",
            payload_utf8=b"",
            raw_bytes=b"",
            status="new",
        )
        self._open_edit_dialog(ev)

    def _on_resend_event(self, ev_id: int):
        row = self._model.row_for_id(ev_id)
        ev = self._model.event_at_row(row)
        if ev is None:
            return
        cmd = {
            "type": "command",
            "command": "resend",
            "id": ev.id,
            "name": ev.name,
            "direction": ev.direction,
            "event_type": ev.event_type,
            "payload_utf8": (ev.payload_utf8 or b"").decode("utf-8", errors="replace"),
            "raw_hex": (ev.raw_bytes or b"").hex(),
        }
        self._send_command_to_sniffer(cmd)

        out = NetEvent(
            time=QDateTime.currentDateTime(),
            direction=ev.direction,
            event_type=ev.event_type,
            name=ev.name,
            payload_utf8=ev.payload_utf8,
            raw_bytes=ev.raw_bytes,
            status="sent (resend)",
        )
        self._model.add_event(out)
        row = self._model.rowCount() - 1
        self._table.setRowHidden(row, not self._event_matches_filter(out))

    def _on_resend_selected(self):
        ev_id = self._selected_event_id()
        if ev_id is None:
            return
        self._on_resend_event(ev_id)

    def _on_send_requested(self, ev: NetEvent):
        cmd = {
            "type": "command",
            "command": "send",
            "name": ev.name,
            "direction": ev.direction,
            "event_type": ev.event_type,
            "payload_utf8": (ev.payload_utf8 or b"").decode("utf-8", errors="replace"),
        }
        if ev.use_raw_bytes:
            cmd["raw_hex"] = (ev.raw_bytes or b"").hex()
        self._send_command_to_sniffer(cmd)

        ev.time = QDateTime.currentDateTime()
        ev.status = "sent (edited)"
        self._model.add_event(ev)
        row = self._model.rowCount() - 1
        self._table.setRowHidden(row, not self._event_matches_filter(ev))

    def _open_edit_dialog(self, ev: NetEvent):
        dlg = EditDialog(ev, self)
        dlg.sendRequested.connect(self._on_send_requested)
        dlg.finished.connect(lambda _: self._open_dialogs.remove(dlg))
        self._open_dialogs.append(dlg)
        dlg.open()

    def _send_command_to_sniffer(self, obj: dict):
        if self._sniffer_source is None:
            return
        self._sniffer_source.send_command(obj)


def _dispatch_command(cmd: dict):
    handled = False
    for handler in list(_command_handlers):
        try:
            handler(cmd)
            handled = True
        except Exception as e:
            print(f"GUI command handler error: {e}")
    if not handled:
        print(f"GUI command: {cmd}")


def register_command_handler(handler):
    if handler is None:
        return
    _command_handlers.append(handler)


def _build_net_event(result, direction):
    ev = NetEvent()
    ev.direction = direction
    ev.event_type = result.get("event_type", "") or result.get("packet_type", "")
    ev.name = result.get("event_name", "")
    ev.payload_utf8 = _payload_to_utf8(_safe_json(result.get("event_data")))
    ev.raw_bytes = bytes.fromhex(result.get("raw_event_data", "") or "")
    ev.status = "captured"
    return ev


def send_event_to_gui(result, direction):
    with _gui_lock:
        if _gui_source is None:
            _pending_events.append((result, direction))
            return
        source = _gui_source
    ev = _build_net_event(result, direction)
    source.inject_event(ev)


def start_gui():
    global _gui_app, _gui_source
    app = QApplication.instance()
    if app is None:
        app = QApplication([])

    signal_timer = QTimer()
    signal_timer.setInterval(200)
    signal_timer.timeout.connect(lambda: None)
    signal_timer.start()

    source = InProcessEventSource()
    source.commandIssued.connect(_dispatch_command)
    window = MainWindow(event_source=source)
    window.show()

    with _gui_lock:
        _gui_app = app
        _gui_source = source
        pending = list(_pending_events)
        _pending_events.clear()

    for result, direction in pending:
        ev = _build_net_event(result, direction)
        source.inject_event(ev)

    return app.exec()


def request_quit():
    with _gui_lock:
        app = _gui_app
    if app is not None:
        app.quit()


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
