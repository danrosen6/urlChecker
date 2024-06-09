import sys
import threading
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLineEdit, QPushButton, QLabel
from PySide6.QtCore import QTimer, Signal
from url_analysis import analyze_url
from virus_total_analysis import initiate_virus_total_analysis

# Define the main window class for the URL checker application.
class URLCheckerWindow(QMainWindow):
    # Define a custom signal for communicating virus total analysis completion.
    virus_total_complete_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("URL Checker")  # Set the window title.
        self.setGeometry(300, 300, 500, 500)  # Set the window position and size.

        central_widget = QWidget(self)  # Create a central widget.
        self.setCentralWidget(central_widget)  # Set the central widget of the window.
        layout = QVBoxLayout(central_widget)  # Create a vertical layout for the widgets.

        self.url_input = QLineEdit(self)  # Text input field for URLs.
        self.check_button = QPushButton("Check URL", self)  # Button to trigger URL check.
        self.results_text = QLabel("", self)  # Label to display the results of URL check.
        self.results_text.setWordWrap(True)  # Enable word wrapping for the label.

        self.virus_total_button = QPushButton("Analyze with VirusTotal", self)  # Button for VirusTotal analysis.
        self.virus_total_results = QLabel("", self)  # Label to display VirusTotal analysis results.
        self.virus_total_results.setWordWrap(True)
        self.virus_total_timer = QTimer(self)  # Timer for handling analysis countdown.
        self.virus_total_timer.setInterval(1000)  # Timer interval set to 1 second.
        self.virus_total_time_left = 15  # Initial time left for analysis countdown.

        # Add widgets to the layout.
        layout.addWidget(QLabel("Enter the URL:"))
        layout.addWidget(self.url_input)
        layout.addWidget(self.check_button)
        layout.addWidget(self.results_text)
        layout.addWidget(self.virus_total_button)
        layout.addWidget(self.virus_total_results)

        # Connect button click events to their respective methods.
        self.check_button.clicked.connect(self.check_url)
        self.virus_total_button.clicked.connect(lambda: self.start_analysis(
            self.virus_total_button, self.virus_total_timer, 
            initiate_virus_total_analysis, self.virus_total_complete_signal))

        # Connect the signal to update the results when analysis is complete.
        self.virus_total_complete_signal.connect(lambda report: self.update_results(report, self.virus_total_results))

    def start_analysis(self, button, timer, analysis_func, signal):
        # Start URL analysis and manage timer for countdown
        url = self.url_input.text()
        self.reset_timer(timer, button)  # Reset the timer and button state before starting
        update_func = lambda: self.update_countdown(button, timer)
        timer.timeout.connect(update_func)
        timer.start()
        threading.Thread(target=analysis_func, args=(url, signal.emit), daemon=True).start()
        self.virus_total_update_func = update_func

    def reset_timer(self, timer, button):
        timer.stop()
        if timer.isActive():  # Check if the timer is active before attempting to disconnect
            timer.timeout.disconnect()  # Disconnect all connections to avoid multiple triggers
        self.virus_total_time_left = 15  # Reset the countdown
        button.setText("Analyze with VirusTotal")

    def update_countdown(self, button, timer):
        # Update the countdown and modify button text accordingly
        self.virus_total_time_left -= 1
        time_left = self.virus_total_time_left
        if time_left <= 0:
            timer.stop()
            if timer.isActive():
                timer.timeout.disconnect(self.virus_total_update_func)
            button.setEnabled(True)
            button.setText("Analyze with VirusTotal")
        else:
            button.setText(f"Analyzing... ({time_left}s)")

    def update_results(self, report, label):
        # Display analysis results in the designated label
        label.setText(report)

    def check_url(self):
        # Check the URL by calling analyze_url and display results
        url = self.url_input.text()
        result = analyze_url(url)
        self.results_text.setText(result)

# Entry point of the application.
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = URLCheckerWindow()
    window.show()
    sys.exit(app.exec())
