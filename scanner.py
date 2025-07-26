# VirusTotal Clipboard Utility
# A background utility that monitors the clipboard for URLs, scans them using the
# VirusTotal API, and provides desktop notifications with the results.

# --- Standard Library Imports ---
import sys
import os
import threading
import time
import re
import webbrowser
import base64

# --- Third-Party Library Imports ---
import keyboard
import pyperclip
import requests
import validators
from plyer import notification
from pystray import MenuItem as item, Icon as icon
from PIL import Image, ImageDraw
from dotenv import load_dotenv

# --- Helper Functions ---

def resource_path(relative_path):
    """
    Get the absolute path to a resource, which works for both development
    and for a packaged PyInstaller application.
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # In a normal development environment, use the file's directory
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

# --- Main Application Class ---

class HybridClipboardScanner:
    """
    Manages the application's core logic, including clipboard monitoring,
    API interaction, hotkeys, and system tray presence.
    """
    def __init__(self, api_key):
        """Initializes the application state and configuration."""
        if not api_key:
            raise ValueError("API key cannot be None.")
        
        self.api_key = api_key
        self.vt_url = "https://www.virustotal.com/api/v3/urls"
        
        # State variables
        self.monitoring_active = False
        self.monitoring_thread = None
        self.last_clipboard_content = ""
        self.last_scanned_url = None
        self.tray_icon = None

    def setup_hotkeys(self):
        """Registers the global hotkeys for controlling the application."""
        try:
            keyboard.add_hotkey('ctrl+alt+shift+s', self.toggle_monitoring)
            keyboard.add_hotkey('ctrl+alt+shift+r', self.show_advanced_report)
            keyboard.add_hotkey('ctrl+alt+shift+q', self.quit_app)
            print("Hotkeys registered:")
            print("Toggle Monitoring: Ctrl+Alt+Shift+S")
            print("Advanced Report: Ctrl+Alt+Shift+R")
            print("Quit Application:  Ctrl+Alt+Shift+Q")
        except Exception as e:
            print(f"Failed to register hotkeys. May require admin privileges. Error: {e}")

    def toggle_monitoring(self):
        """Toggles the clipboard monitoring state between on and off."""
        if self.monitoring_active:
            self.stop_monitoring()
        else:
            self.start_monitoring()

    def start_monitoring(self):
        """Starts the clipboard monitoring thread."""
        if self.monitoring_active:
            return
        
        # Take a snapshot of the current clipboard to ignore its content
        try:
            self.last_clipboard_content = pyperclip.paste()
            if self.last_clipboard_content:
                self.show_notification("Monitoring Started", "Ignoring initial clipboard content.")
            else:
                self.show_notification("Monitoring Enabled", "Clipboard URL scanner is now active.")
        except Exception:
            self.last_clipboard_content = ""

        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self.monitor_clipboard, daemon=True)
        self.monitoring_thread.start()
        print("Monitoring has been enabled.")

    def stop_monitoring(self):
        """Stops the clipboard monitoring thread."""
        if not self.monitoring_active:
            return
        self.monitoring_active = False
        self.show_notification("Monitoring Disabled", "Clipboard URL scanner is now inactive.")
        print("Monitoring has been disabled.")

    def monitor_clipboard(self):
        """
        The main loop that runs in a background thread to check for new
        URLs in the clipboard.
        """
        while self.monitoring_active:
            try:
                current_content = pyperclip.paste()
                # Check if the clipboard has new, non-empty content
                if current_content and current_content != self.last_clipboard_content:
                    self.last_clipboard_content = current_content
                    url = self.extract_url(current_content)
                    if url:
                        # Notify the user that a scan is beginning
                        self.show_notification("Scan in Progress", f"Scanning link: {url.split('://', 1)[-1]}")
                        print(f"URL detected via monitoring: {url}")
                        # Run the scan in a separate thread to keep the app responsive
                        scan_thread = threading.Thread(target=self.scan_url, args=(url,), daemon=True)
                        scan_thread.start()
            
            # This handles a common error when waking the PC from sleep
            except pyperclip.PyperclipException:
                time.sleep(2) # Give the system time to recover clipboard access
            except Exception as e:
                print(f"An unexpected error occurred in the monitoring loop: {e}")
            
            time.sleep(1) # Wait 1 second before checking again

    def extract_url(self, text):
        """
        Extracts and validates a URL from a string, intelligently adding a
        protocol if it's missing (e.g., turning 'google.com' into 'https://google.com').
        """
        if not text:
            return None
        clean_text = text.strip()

        # Pattern 1: Look for a complete URL with a protocol
        full_url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        found_full_urls = re.findall(full_url_pattern, clean_text)
        if found_full_urls and validators.url(found_full_urls[0]):
            return found_full_urls[0]

        # Pattern 2: If no full URL is found, look for a partial one (e.g., "google.com")
        partial_url_pattern = r'(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z.]{2,6})(?:[/\?].*)?'
        found_partial_urls = re.findall(partial_url_pattern, clean_text)
        if found_partial_urls:
            potential_url = f"<https://{found_partial_urls>[0]}"
            return potential_url
        
        return None

    def scan_url(self, url):
        """Submits a URL to VirusTotal and polls for the report."""
        headers = {'x-apikey': self.api_key}
        # Submit the URL for analysis
        try:
            response = requests.post(self.vt_url, headers=headers, data={'url': url})
            response.raise_for_status()
            analysis_id = response.json()['data']['id']
        except requests.exceptions.RequestException as e:
            print(f"Error submitting URL: {e}")
            self.show_notification("API Error", "Could not submit URL. Check API key and connection.")
            return

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        # Poll the analysis endpoint until the report is complete
        while True:
            try:
                report_response = requests.get(analysis_url, headers=headers)
                report_response.raise_for_status()
                report = report_response.json()
                
                if report['data']['attributes']['status'] == 'completed':
                    stats = report['data']['attributes']['stats']
                    self.last_scanned_url = url
                    self.process_report(stats, url)
                    break # Exit the loop once the report is ready
                    
                print("Analysis in progress, waiting...")
                # Wait before polling again to respect API rate limits
                time.sleep(3)
            except requests.exceptions.RequestException as e:
                print(f"Error fetching report: {e}")
                self.show_notification("API Error", "Could not fetch scan report.")
                return

    def process_report(self, stats, url):
        """Analyzes the scan results and triggers a final notification."""
        malicious_votes = stats.get('malicious', 0)
        suspicious_votes = stats.get('suspicious', 0)
        total_flags = malicious_votes + suspicious_votes

        if total_flags > 0:
            title = "🚨 Unsafe Link Detected!"
            message = f"{total_flags} security vendors flagged this URL.\n{url}"
        else:
            title = "✅ Link Appears Safe"
            message = f"No threats detected for:\n{url}"
        
        self.show_notification(title, message)

    def show_notification(self, title, message):
        """Displays a desktop notification with a specified title and message."""
        try:
            notification.notify(
                title=title, 
                message=message, 
                app_name='VirusTotal Clipboard Utility', 
                timeout=4
            )
        except Exception as e:
            print(f"Notification failed: {e}")

    def show_advanced_report(self):
        """Opens a detailed report on the VirusTotal website for the last scanned URL."""
        if not self.last_scanned_url:
            self.show_notification("No Report Available", "Please scan a URL first.")
            return
            
        # Construct the VirusTotal GUI link from the URL
        url_id = base64.urlsafe_b64encode(self.last_scanned_url.encode()).decode().strip("=")
        gui_link = f"https://www.virustotal.com/gui/url/{url_id}/detection"
        webbrowser.open(gui_link)

    def quit_app(self):
        """Stops the application gracefully and cleans up resources."""
        # Show a notification confirming the shutdown
        if self.monitoring_active:
            self.show_notification("Shutting Down", "Disabling monitoring and quitting the utility.")
        else:
            self.show_notification("Shutting Down", "Closing the VirusTotal Clipboard Utility.")

        print("Quit signal received. Shutting down.")
        self.stop_monitoring()
        keyboard.unhook_all()
        if self.tray_icon:
            self.tray_icon.stop()

    def run(self):
        """Sets up and runs the main application event loop."""
        self.setup_hotkeys()
        
        # Load the icon for the system tray
        try:
            image = Image.open(resource_path("app_icon.ico"))
        except FileNotFoundError:
            print("app_icon.ico not found. Creating a default icon.")
            image = Image.new('RGB', (64, 64), color='blue')
            draw = ImageDraw.Draw(image)
            draw.text((10, 25), "URL", fill='white')

        # Define the system tray menu
        menu = (
            item('Toggle Monitoring (Ctrl+Alt+Shift+S)', self.toggle_monitoring),
            item('Advanced Report (Ctrl+Alt+Shift+R)', self.show_advanced_report),
            item('Quit (Ctrl+Alt+Shift+Q)', self.quit_app)
        )
        self.tray_icon = icon("VirusTotal Clipboard Utility", image, "VirusTotal Clipboard Utility", menu)

        # Show a startup notification and start the application
        self.show_notification("Application Started", "The VirusTotal Clipboard Utility is now running.")
        self.tray_icon.run()

# --- Script Entry Point ---

if __name__ == '__main__':
    # Load environment variables from the .env file
    load_dotenv()
    
    # Securely retrieve the API key from the environment
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    
    # Check if the API key exists before starting the application
    if not VIRUSTOTAL_API_KEY:
        print("CRITICAL: API key not found. Please create a .env file and add your VIRUSTOTAL_API_KEY.")
        # Notify the user of the configuration error
        notification.notify(
            title="Configuration Error",
            message="API key not found. Please create a .env file.",
            app_name="VirusTotal Clipboard Utility",
            timeout=10
        )
    else:
        # If the key is found, create an instance of the app and run it
        app = HybridClipboardScanner(VIRUSTOTAL_API_KEY)
        app.run()
