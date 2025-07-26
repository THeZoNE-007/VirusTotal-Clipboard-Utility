![image alt](https://github.com/THeZoNE-007/VirusTotal-Clipboard-Utility/blob/761580b87bd1376a87a3b3f050db182bc509ebaf/Banner.jpg)
 # VirusTotal-Clipboard-Utility

VirusTotal-Clipboard-Utility is a lightweight, privacy-focused Windows utility that runs in the background to monitor your clipboard for URLs. It automatically scans them against the VirusTotal API in real-time and provides instant desktop notifications about their safety, helping you avoid malicious websites without disrupting your workflow.

The application is activated and controlled entirely through global hotkeys, ensuring it only monitors your clipboard when you explicitly tell it to.

## Features

-   **Hotkey-Activated Monitoring:** The core monitoring feature is off by default and can be toggled on or off with a simple hotkey, putting you in complete control.
-   **Comprehensive Desktop Notifications:** Get immediate feedback for every action:
    -   `✅ Application Started`
    -   `▶️ Monitoring Enabled` (and ignores pre-existing clipboard content)
    -   `⏸️ Monitoring Disabled`
    -   `⏳ Scan in Progress...`
    -   `✅ Link Appears Safe`
    -   `🚨 Unsafe Link Detected!`
    -   `⛔ Shutting Down...`
-   **Advanced Report Link:** Instantly open a detailed, comprehensive report on the VirusTotal website for the last scanned URL.
-   **Secure API Key Handling:** Your secret API key is never exposed in the source code or the final executable. It's loaded securely from a local `.env` file.
-   **System Tray Control:** The application runs discreetly in the system tray, with a right-click menu for easy access to its functions.
-   **Intelligent URL Parsing:** Automatically detects and handles URLs copied with or without the `http://` or `https://` prefix.
-   **Robust and Resilient:** Designed to handle common issues like waking the computer from sleep mode.

## Requirements

-   Windows Operating System
-   Python 3.x
-   Git installed on your system
-   A free VirusTotal API Key

## Setup and Installation

Follow these steps to get the application running on your system.

**1. Clone the GitHub Repository**
First, clone the repository to your local machine using Git and navigate into the new folder.

```bash
git clone https://github.com/THeZoNE-007/VirusTotal-Clipboard-Utility.git
cd VirusTotal-Clipboard-Utility
```

**2. Create and Activate a Virtual Environment**
It is highly recommended to use a virtual environment to manage the project's dependencies.

```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
venv\Scripts\activate
```

**3. Install Required Libraries**
The repository includes a `requirements.txt` file that lists all necessary libraries. Install them using a single command:

```bash
pip install -r requirements.txt
```

**4. Create a `.env` File and Add Your API Key**
For security, your API key must be stored in an environment file, not in the code.

1.  In your project's root directory, create a new file named `.env`.
2.  Open the `.env` file and add the following line, replacing the placeholder with your actual key:
    ```
    VIRUSTOTAL_API_KEY="your_actual_api_key_goes_here"
    ```
3.  **Security Note:** The `.gitignore` file in this repository is already configured to ignore the `.env` file, ensuring the api key is never uploaded to GitHub.

## How to Operate the Tool

**1. Run the Application**
Navigate to the project directory in your terminal (with the virtual environment activated) and run the script:

```bash
python scanner.py
```

You will see a "Hotkeys registered" message in the console, an "Application Started" notification will appear, and a new icon will show up in your system tray.

**2. Using the Hotkeys**
The application is controlled entirely through these global hotkeys:

| Hotkey                 | Action                | Description                                                                                  |
| :--------------------- | :-------------------- | :------------------------------------------------------------------------------------------- |
| **`Ctrl+Alt+Shift+S`** | **Toggle Monitoring** | Turns the automatic clipboard scanning mode on or off. You will receive a notification confirming the change. |
| **`Ctrl+Alt+Shift+R`** | **Advanced Report**   | Opens a detailed report page on VirusTotal for the last URL that was scanned.                |
| **`Ctrl+Alt+Shift+Q`** | **Quit Application**  | Shuts down the application gracefully, providing a final notification.                       |

**3. The Standard Workflow**
1.  Press `Ctrl+Alt+Shift+S` to enable monitoring.
2.  Copy a URL from your browser or any document.
3.  A "Scan in Progress" notification will appear.
4.  After a few seconds, a final result notification ("Safe" or "Unsafe") will be displayed.
5.  When you are done, press `Ctrl+Alt+Shift+S` again to disable monitoring.

## Packaging as a Standalone Executable (Optional)

To create a single `.exe` file that can be run on other Windows machines without needing Python, you can use PyInstaller.

**1. Prerequisites**
Make sure PyInstaller is installed in your virtual environment:
```bash
pip install pyinstaller
```

**2. Build the Executable**
Run the following command from your project's root directory. This command includes all necessary flags for a polished, functional build with a custom name and icon.

```bash
pyinstaller --name "VirusTotal Clipboard Utility" --distpath executable --onefile --windowed --add-data "app_icon.ico;." --hidden-import "keyboard._win32" --hidden-import "plyer.platforms.win.notification" --icon="app_icon.ico" scanner.py
```

**3. Locate and Run Your Application**
-   After the build completes, you will find a new folder named `executable`.
-   Inside this folder is your final application: `VirusTotal Clipboard Utility.exe`.
-   **Important:** To run the `.exe` file, you must copy the `.env` file (containing your API key) into the `executable` folder, so it sits right next to the `.exe`.