# FiveM NetCheat

## DISCLAIMER
This software should serve a legititimate purpose only! It is a Man-in-the-Middle framework for testing the security of all applications/games using the ENet UDP communication layer. You should only ever use it on servers on which you have proper authorization to do so. Unauthorized exploitation is illegal, against ToS and may get you banned.

## How to use?
 - Install Python3.10
 - `python -m pip install -r requirements.txt`
 - `python main.py [UPSTREAM IP:PORT]`

If running on Windows, you can also use the supplied binary file from releases.

The Windows executable is self-contained; Python does not need to be installed
on the computer that runs it. Every branch push produces a downloadable GitHub
Actions artifact and publishes `NetCheat.exe` in a GitHub Release tagged to the
exact commit. Pull requests and manual workflow runs produce the artifact only.

### Windows release downloads

Windows may prevent the downloaded `NetCheat.exe` release from starting because the file is not digitally signed and is marked as downloaded from the Internet. If you trust the release and obtained it from this repository, right-click the file, select **Properties**, check **Unblock**, and click **Apply** before running it.

Alternatively, unblock it from PowerShell:

```powershell
Unblock-File .\NetCheat.exe
```

## How it works?
This tool establishes a Man-in-the-Middle proxy for ENet. It may be thought of as a transparent layer connecting you to the server. This enables fully parsing all the events on the ENet network and also modifying them and creating your own. TCP packets and UDP non-ENet packets are just passed through.

## Middlewares

Use the **Middlewares** button in the application to create, import, edit,
enable, disable, delete, and reorder middleware scripts. The manager also
contains built-in examples that can be installed as editable scripts. Scripts
are stored in the `middlewares/` directory beside `NetCheat.exe` (or beside the
source files when running from Python), and reload automatically after changes.
Each file must define exactly one public function.
The function receives every supported FiveM event as a dictionary and returns:

- the event unchanged to forward it;
- a changed event dictionary to rewrite it; or
- `None` to drop it.

```python
def patch(event):
    if event["direction"] == "OUT" and event["name"] == "example:block-me":
        return None
    if event["name"] == "example:rewrite-me":
        event["data"] = ["replacement"]
    return event
```

The dictionary contains `direction`, `type`, `name`, `data`, and `raw_data`.
`raw_data` is a `bytes` value. Changing `data` repacks ordinary net events as
MessagePack; changing `raw_data` rewrites the opaque payload directly. The GUI
colors blocked events red and changed events yellow.

The built-in examples include outbound ANGLE fingerprint randomization, secret
redaction, event-name blocking, and numeric-field clamping. Review and adapt an
example before enabling it; enabled scripts affect live traffic immediately.
