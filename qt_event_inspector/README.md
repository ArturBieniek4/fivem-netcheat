#Event Inspector

GUI for FiveM event sniffer that mimics a tiny slice of Chrome DevTools **Network** panel:

- live log (table) of received events
- per-row **Edit** / **Resend** buttons
- right-side details view (payload + raw)
- quick text filter

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

    Replace it with your own `EventSource` that receives events from your *own *
        application /
    test environment,
    then `connect(...)` to `MainWindow::onEventCaptured`
        .

    ## #TCP bridge(Python sniffer)

        The GUI starts a local TCP server on an ephemeral port and writes the
    port number to a file.The Python sniffer reads that file,
    connects,
    then sends newline -
        delimited JSON events :

```json{
          "type" : "event",
          "direction" : "IN",
          "name" : "Example",
          "payload" : {"k" : "v"},
          "raw_hex" : "..."
        }
```

    GUI
    -
    to -
    python commands are sent back over the same TCP
    connection as JSON lines with `type : "command"`.

                                          Port file lookup
    : -If `EVENT_INSPECTOR_PORT_FILE` is set,
    it is used.-
        Otherwise the GUI writes to the OS temp dir as `inspector_port.txt`
            .

        ##Sending

        The **Send **button in the edit dialog sends the event with the
        specified direction and payload.

        ##Build with qmake(Qt Creator / CLI)

            ## #CLI(Linux / macOS)
```bash qmake make
        -
        j./ qt_event_inspector
```

            ## #CLI(Windows MinGW)
```bat qmake mingw32
        - make -
        j qt_event_inspector
            .exe
```

        Open `qt_event_inspector.pro` in Qt Creator if you prefer the IDE.
