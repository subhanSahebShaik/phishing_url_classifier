# Phishing URL Classification System

The Phishing URL Classification System is a machine learning-based approach to identify and classify phishing URLs using various URL features. This project aims to enhance online security by dynamically analyzing URLs to distinguish between legitimate and malicious web addresses.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Technologies Used](#technologies-used)
- [Contributing](#contributing)

## Introduction

In the digital era, cybersecurity is of paramount importance. Phishing attacks, in particular, pose a significant threat by impersonating trustworthy entities to steal sensitive information from unsuspecting users. The Phishing URL Classification System leverages machine learning algorithms to automatically detect and classify phishing URLs, providing users with real-time warnings about potential threats.

## Features

- **URL Feature Analysis**: The system extracts a diverse range of URL features, including domain length, presence of special characters, protocol type (HTTP/HTTPS), and more.
  
- **Machine Learning Model**: Trained on a comprehensive dataset, the system utilizes a Random Forest classifier to differentiate between legitimate and phishing URLs.
  
- **Real-Time Detection**: Users receive instant warnings when accessing suspicious URLs, helping prevent potential security breaches.

## Installation

To use the Phishing URL Classification System locally, follow these steps:

1. Clone the repository:
   ```cmd
   git clone https://github.com/your-username/phishing-url-classification.git

2. Navigate to the project directory:
   ```cmd
   cd phishing-url-classification/backend

3. Install the required Python libraries:
   ```cmd
   pip install -r requirements.txt

## Usage
1. Launch the Django server:
   ```cmd
   python manage.py runserver

2. Access the system through a terminal:
   ```cmd
   http://localhost:8000/

## Technologies Used
- Python
- Django
- Pandas
- Scikit-learn
- React JS

## Contributing
Contributions are welcome! If you have suggestions, bug reports, or feature requests, please open an issue or submit a pull request..
