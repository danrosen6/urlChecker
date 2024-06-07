import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLineEdit, QPushButton, QLabel
from PySide6.QtCore import Qt
from url_analysis import analyze_url
from virus_total_analysis import get_virus_total_report

# Define a class for the main window of the application
class URLCheckerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("URL Checker")  # Title of the main window
        self.setGeometry(300, 300, 500, 300)  # Initial position and size of the window
        self.setMaximumWidth(700)  # Limit the maximum width of the window

        # Set up the central widget and layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Create interface elements
        self.url_input = QLineEdit(self)  # Input field for URLs
        self.check_button = QPushButton("Check URL", self)  # Button to trigger URL check
        self.results_text = QLabel("", self)  # Label to display the analysis results
        self.results_text.setWordWrap(True)  # Enable text wrapping for better readability
        self.virus_total_button = QPushButton("Analyze with VirusTotal", self)  # Button for VirusTotal analysis
        self.virus_total_results = QLabel("", self)  # Label to display VirusTotal results
        self.virus_total_results.setWordWrap(True)  # Enable text wrapping here as well

        # Add widgets to the layout
        layout.addWidget(QLabel("Enter the URL:"))
        layout.addWidget(self.url_input)
        layout.addWidget(self.check_button)
        layout.addWidget(self.results_text)
        layout.addWidget(self.virus_total_button)
        layout.addWidget(self.virus_total_results)

        # Connect button clicks to their respective functions
        self.check_button.clicked.connect(self.check_url)
        self.virus_total_button.clicked.connect(self.analyze_with_virustotal)

    def check_url(self):
        # Get the URL from input and analyze it
        url = self.url_input.text()
        result = analyze_url(url)  # Assumes analyze_url returns a string
        self.results_text.setText(result)

    def analyze_with_virustotal(self):
        # Get the URL from input and fetch the VirusTotal report
        url = self.url_input.text()
        report = get_virus_total_report(url)  # Assumes this function returns a string
        self.virus_total_results.setText(report)

# Start the application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = URLCheckerWindow()
    window.show()
    sys.exit(app.exec())
