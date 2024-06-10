# Import necessary modules and libraries
import sys  # sys is used to interact with the Python interpreter
import threading  # threading is used to run tasks in separate threads
from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget,
                               QLineEdit, QPushButton, QTextEdit, QLabel)  # Importing GUI components
from PySide6.QtCore import QTimer, Signal  # QTimer for timing events, Signal for inter-object communication
from PySide6.QtGui import QTextOption  # QTextOption for configuring text display options
from url_decomposition import analyze_url  # Import the function to analyze URLs
from virus_total_analysis import initiate_virus_total_analysis  # Import the function to analyze URLs with VirusTotal

# Define the main window class derived from QMainWindow
class URLCheckerWindow(QMainWindow):
    virus_total_complete_signal = Signal(str)  # Signal to emit results of VirusTotal analysis
    url_analysis_complete_signal = Signal(str)  # Signal to emit results of URL analysis

    def __init__(self):
        super().__init__()  # Call the constructor of the parent class
        self.setWindowTitle("URL Analysis")  # Set the window title
        self.setGeometry(300, 300, 600, 600)  # Set window size and position

        # Create a central widget and set the layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(10)  # Set spacing between widgets

        # Initialize UI components
        self.url_input = QLineEdit(self)  # Text input for URLs
        self.check_button = QPushButton("Decompose URL", self)  # Button to start URL decomposition
        self.results_text = QTextEdit(self)  # Text area to display results
        self.results_text.setReadOnly(True)  # Make the text area read-only
        self.results_text.setWordWrapMode(QTextOption.WordWrap)  # Enable word wrapping

        self.virus_total_button = QPushButton("Analyze with VirusTotal", self)  # Button for VirusTotal analysis
        self.virus_total_results = QTextEdit(self)  # Text area for VirusTotal results
        self.virus_total_results.setReadOnly(True)
        self.virus_total_results.setWordWrapMode(QTextOption.WordWrap)
        self.virus_total_timer = QTimer(self)  # Timer to handle countdown for analysis
        self.virus_total_timer.setInterval(1000)  # Set timer interval to 1 second
        self.virus_total_time_left = 15  # Set initial countdown time

        # Add widgets to the layout
        layout.addWidget(QLabel("Enter the URL:"))
        layout.addWidget(self.url_input)
        layout.addWidget(self.check_button)
        layout.addWidget(self.results_text)
        layout.addWidget(self.virus_total_button)
        layout.addWidget(self.virus_total_results)

        # Connect signals and slots
        self.check_button.clicked.connect(self.start_url_analysis)  # Connect button click to analysis start
        self.virus_total_button.clicked.connect(self.start_virus_total_analysis)
        self.virus_total_timer.timeout.connect(self.update_countdown)

        self.virus_total_complete_signal.connect(self.update_virus_total_results)
        self.url_analysis_complete_signal.connect(self.update_url_analysis_results)  # Connect URL analysis results signal

    def start_url_analysis(self):
        url = self.url_input.text()  # Get text from input
        threading.Thread(target=self.check_url, args=(url,), daemon=True).start()  # Start analysis in a new thread

    def check_url(self, url):
        result = analyze_url(url)  # Perform URL analysis
        self.url_analysis_complete_signal.emit(result)  # Emit the results

    def update_url_analysis_results(self, result):
        self.results_text.setText(result)  # Display the results in the text area

    def start_virus_total_analysis(self):
        url = self.url_input.text()
        self.reset_timer()  # Reset the timer
        threading.Thread(target=initiate_virus_total_analysis, args=(url, self.virus_total_complete_signal.emit), daemon=True).start()

    def reset_timer(self):
        self.virus_total_time_left = 15  # Reset the countdown timer
        self.virus_total_timer.start()  # Start the timer
        self.update_countdown()

    def update_countdown(self):
        self.virus_total_time_left -= 1  # Decrement the countdown
        if self.virus_total_time_left <= 0:
            self.virus_total_timer.stop()  # Stop the timer
            self.virus_total_button.setEnabled(True)
            self.virus_total_button.setText("Analyze with VirusTotal")
        else:
            self.virus_total_button.setText(f"Analyzing... ({self.virus_total_time_left}s)")  # Update button text

    def update_virus_total_results(self, report):
        self.virus_total_results.setText(report)  # Display VirusTotal results
        self.virus_total_button.setEnabled(True)  # Re-enable the button

if __name__ == "__main__":
    app = QApplication(sys.argv)  # Create the application object
    window = URLCheckerWindow()  # Create the main window
    window.show()  # Show the main window
    sys.exit(app.exec())  # Start the event loop
