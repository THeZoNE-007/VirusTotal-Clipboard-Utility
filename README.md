![image alt](https://github.com/THeZoNE-007/VirusTotal-Clipboard-Utility/blob/761580b87bd1376a87a3b3f050db182bc509ebaf/Banner.jpg)
 # VirusTotal-Clipboard-Utility
VirusTotal-Clipboard-Utility is a lightweight, privacy-focused background utility that monitors your clipboard for URLs and scans them against the VirusTotal API in real-time. It lives in your system tray and provides instant desktop notifications about the safety of copied links, helping you avoid malicious websites without disrupting your workflow.

The application is activated and controlled entirely through global hotkeys, ensuring it only monitors your clipboard when you explicitly tell it to.

## Features

-   **Hotkey-Activated Monitoring:** The core monitoring feature is off by default and can be toggled on or off with a simple hotkey, putting you in complete control.
-   **Real-Time Threat Detection:** Leverages the power of VirusTotal's 70+ antivirus engines to accurately assess the safety of URLs.
-   **Instant Desktop Notifications:** Get immediate "✅ Safe" or "🚨 Unsafe" notifications the moment a scan is complete.
-   **Advanced Report Link:** Instantly open a detailed, comprehensive report on the VirusTotal website for the last scanned URL.
-   **System Tray Control:** The application runs discreetly in the system tray, with a right-click menu for easy access to its functions.
-   **Intelligent URL Parsing:** Automatically detects and handles URLs copied with or without the `http://` or `https://` prefix.
-   **Robust and Resilient:** Designed to handle common issues like waking from sleep mode and to ignore content already in the clipboard when monitoring is first enabled.

## Requirements

-   Python 3.x
-   A free VirusTotal API Key

## Setup and Installation

Follow these steps to get the application running on your system.

**1. Create a Project Folder and Virtual Environment**
It is highly recommended to use a virtual environment to manage the project's dependencies.

```bash
# Create and navigate into the project directory
mkdir url-scanner
cd url-scanner

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

**2. Create the `requirements.txt` file**
Create a new file named `requirements.txt` in your project directory (`url-scanner/`) and add the following lines to it. This file lists all the libraries the project needs.

```text
keyboard
pyperclip
requests
pystray
plyer
validators
Pillow
```

**3. Install Required Libraries**
Now, install all the necessary Python packages from the `requirements.txt` file using a single command:

```bash
pip install -r requirements.txt
```

**4. Add Your VirusTotal API Key**
This is the most critical step.
1.  Open the `scanner.py` file in a text editor.
2.  Find the line at the bottom of the file:
    ```python
    VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
    ```
3.  Replace `"YOUR_VIRUSTOTAL_API_KEY_HERE"` with your actual API key from your VirusTotal account.

## How to Operate the Tool

**1. Run the Application**
Navigate to your project directory in your terminal (with the virtual environment activated) and run the script:

```bash
python scanner.py
```

You will see a message in the console confirming that the hotkeys have been registered, and a new icon will appear in your system tray (bottom-right corner of the screen).

**2. Using the Hotkeys**
The application is controlled entirely through these global hotkeys:

| Hotkey | Action | Description |
| :--- | :--- | :--- |
| **`Ctrl+Alt+Shift+S`** | **Toggle Monitoring** | Turns the automatic clipboard scanning mode on or off. You will receive a notification confirming the change. |
| **`Ctrl+Alt+Shift+R`** | **Advanced Report** | Opens a detailed report page on VirusTotal for the last URL that was scanned. |
| **`Ctrl+Alt+Shift+Q`** | **Quit Application** | Shuts down the application gracefully. |

**3. The Standard Workflow**
1.  Press `Ctrl+Alt+Shift+S` to enable monitoring.
2.  Copy a URL from your browser or any document.
3.  Wait a few seconds for the scan to complete. A desktop notification will appear with the result.
4.  When you are done, press `Ctrl+Alt+Shift+S` again to disable monitoring.

**4. Stopping the Application**
You can close the application in two ways:
-   Press the **`Ctrl+Alt+Shift+Q`** hotkey.
-   **Right-click** the application's icon in the system tray and select **"Quit"** from the menu.