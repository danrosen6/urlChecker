import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLineEdit, QPushButton, QLabel
from PySide6.QtCore import Qt, QTimer, Signal
from url_analysis import analyze_url
from virus_total_analysis import initiate_virus_total_analysis
import threading

class URLCheckerWindow(QMainWindow):
    report_ready_signal = Signal(str)  # Custom signal for updating the GUI with results from background thread

    def __init__(self):
        super().__init__()
        self.setWindowTitle("URL Checker")  # Set the window title
        self.setGeometry(300, 300, 500, 300)  # Set the window position and size
        self.setMaximumWidth(700)  # Set the maximum width of the window

        central_widget = QWidget(self)  # Main widget that holds other widgets
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)  # Layout manager to arrange widgets vertically

        # URL input field
        self.url_input = QLineEdit(self)
        # Button to trigger URL checking
        self.check_button = QPushButton("Check URL", self)
        # Label to display results of URL analysis
        self.results_text = QLabel("", self)
        self.results_text.setWordWrap(True)
        # Button to initiate VirusTotal analysis
        self.virus_total_button = QPushButton("Analyze with VirusTotal", self)
        # Label to display results from VirusTotal analysis
        self.virus_total_results = QLabel("", self)
        self.virus_total_results.setWordWrap(True)
        # Label for showing countdown or status messages
        self.countdown_label = QLabel("Ready", self)

        # Adding widgets to the layout
        layout.addWidget(QLabel("Enter the URL:"))
        layout.addWidget(self.url_input)
        layout.addWidget(self.check_button)
        layout.addWidget(self.results_text)
        layout.addWidget(self.virus_total_button)
        layout.addWidget(self.virus_total_results)
        layout.addWidget(self.countdown_label)

        # Connecting button clicks to corresponding methods
        self.check_button.clicked.connect(self.check_url)
        self.virus_total_button.clicked.connect(self.start_virus_total_analysis)
        self.report_ready_signal.connect(self.update_results)

        # Timer for countdown during analysis
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_timer)
        self.duration = 15  # Duration of the countdown

    def update_timer(self):
        # Update the countdown every second, stop timer and update label when done
        if self.duration > 0:
            self.duration -= 1
            self.countdown_label.setText(f"{self.duration} seconds remaining")
        else:
            self.timer.stop()
            self.countdown_label.setText("Waiting for results...")

    def check_url(self):
        # Get URL from input, analyze it, and display the result
        url = self.url_input.text()
        result = analyze_url(url)
        self.results_text.setText(result)

    def start_virus_total_analysis(self):
        # Start VirusTotal analysis in a separate thread to keep UI responsive
        url = self.url_input.text()
        self.duration = 15  # Reset the countdown
        self.timer.start(1000)  # Start the timer, triggering it every second
        threading.Thread(target=initiate_virus_total_analysis, args=(url, self.report_ready_signal.emit), daemon=True).start()

    def update_results(self, report):
        # Update the GUI with the results from the VirusTotal analysis
        self.virus_total_results.setText(report)
        self.timer.stop()
        self.countdown_label.setText("Analysis complete!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = URLCheckerWindow()
    window.show()
    sys.exit(app.exec())
