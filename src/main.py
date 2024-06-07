import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLineEdit, QPushButton, QLabel
from PySide6.QtCore import Qt, QTimer
from url_analysis import analyze_url
from virus_total_analysis import get_virus_total_report
import threading  # Import threading for non-blocking API calls

class URLCheckerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("URL Checker")
        self.setGeometry(300, 300, 500, 300)
        self.setMaximumWidth(700)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.url_input = QLineEdit(self)
        self.check_button = QPushButton("Check URL", self)
        self.results_text = QLabel("", self)
        self.results_text.setWordWrap(True)
        self.virus_total_button = QPushButton("Analyze with VirusTotal", self)
        self.virus_total_results = QLabel("", self)
        self.virus_total_results.setWordWrap(True)
        self.countdown_label = QLabel("Ready", self)

        layout.addWidget(QLabel("Enter the URL:"))
        layout.addWidget(self.url_input)
        layout.addWidget(self.check_button)
        layout.addWidget(self.results_text)
        layout.addWidget(self.virus_total_button)
        layout.addWidget(self.virus_total_results)
        layout.addWidget(self.countdown_label)

        self.check_button.clicked.connect(self.check_url)
        self.virus_total_button.clicked.connect(self.start_virus_total_analysis)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_timer)
        self.duration = 15

    def update_timer(self):
        if self.duration > 0:
            self.duration -= 1
            self.countdown_label.setText(f"{self.duration} seconds remaining")
        else:
            self.timer.stop()
            self.countdown_label.setText("Analysis complete!")

    def check_url(self):
        url = self.url_input.text()
        result = analyze_url(url)
        self.results_text.setText(result)

    def start_virus_total_analysis(self):
        url = self.url_input.text()
        self.duration = 15  # Reset the countdown
        self.timer.start(1000)  # Start the timer
        # Start the analysis in a separate thread to prevent GUI freezing
        threading.Thread(target=self.analyze_with_virustotal, args=(url,), daemon=True).start()

    def analyze_with_virustotal(self, url):
        report = get_virus_total_report(url)
        self.virus_total_results.setText(report)
        self.timer.stop()  # Stop the timer once the report is fetched

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = URLCheckerWindow()
    window.show()
    sys.exit(app.exec())
