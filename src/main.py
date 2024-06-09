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
            initiate_virus_total_analysis, self.virus_total_complete_signal, 'virus_total'))

        # Connect the signal to update the results when analysis is complete.
        self.virus_total_complete_signal.connect(lambda report: self.update_results(report, self.virus_total_results))

    # Method to start the URL analysis process.
    def start_analysis(self, button, timer, analysis_func, signal, timer_type):
        url = self.url_input.text()
        button.setEnabled(False)
        update_func = lambda: self.update_countdown(button, timer, timer_type)
        timer.timeout.connect(update_func)
        timer.start()
        threading.Thread(target=analysis_func, args=(url, signal.emit), daemon=True).start()
        self.virus_total_update_func = update_func

    # Method to update the countdown of the analysis timer.
    def update_countdown(self, button, timer, timer_type):
        self.virus_total_time_left -= 1
        time_left = self.virus_total_time_left

        if time_left <= 0:
            timer.stop()
            timer.timeout.disconnect(self.virus_total_update_func)
            button.setEnabled(True)
            button.setText("Analyze")
        else:
            button.setText(f"Analyzing... ({time_left}s)")

    # Method to display analysis results in the label.
    def update_results(self, report, label):
        label.setText(report)

    # Method to check the URL when the check button is clicked.
    def check_url(self):
        url = self.url_input.text()
        result = analyze_url(url)
        self.results_text.setText(result)

# Entry point of the application.
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = URLCheckerWindow()
    window.show()
    sys.exit(app.exec())
