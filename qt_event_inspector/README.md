# Event Inspector (Qt prototype)

A minimal Qt **Widgets** prototype that mimics a tiny slice of Chrome DevTools **Network** panel:

- live log (table) of received events
- per-row **Edit** / **Resend** buttons
- right-side details view (payload + raw)
- quick text filter
- dummy event generator (so you can test UI immediately)

> NOTE: This repo is intentionally **generic** and **safe**. It does **not** include any logic for intercepting or manipulating third-party traffic. Plug it into an **authorized** source of events.

## Build (Qt6 preferred, Qt5 OK)

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j
```

Run the produced executable (`EventInspectorQt`).

## Where to hook your real events

`DummyEventSource` emits:

```cpp
signals:
  void eventCaptured(NetEvent ev);
```

Replace it with your own `EventSource` that receives events from your *own* application / test environment, then `connect(...)` to `MainWindow::onEventCaptured`.

## Sending

The **Send** button in the edit dialog only emits a Qt signal (`sendRequested`) and the prototype logs it back as an `OUT` event. Replace `MainWindow::onSendRequested` with a call to your backend.


## Build with qmake (Qt Creator / CLI)

### CLI (Linux/macOS)
```bash
qmake
make -j
./qt_event_inspector
```

### CLI (Windows MinGW)
```bat
qmake
mingw32-make -j
qt_event_inspector.exe
```

Open `qt_event_inspector.pro` in Qt Creator if you prefer the IDE.
