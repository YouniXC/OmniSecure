# OmniSecure 🛡️: Intelligent Email Defense & Forensic System

OmniSecure is a lightweight, client-side endpoint security application designed to detect, block, and analyze advanced email threats, specifically targeting Zero-Day Phishing and "Quishing" (QR Code Phishing). 

## 🚀 The Problem & Solution
Standard enterprise spam filters often miss malicious payloads hidden inside images (Quishing) and struggle with context-heavy social engineering attacks crafted by Generative AI. 

OmniSecure acts as a localized defense layer. It analyzes both the semantic intent of emails and the visual structure of attachments locally, ensuring maximum privacy by not uploading user emails to a centralized cloud database.

## 🧠 Core Architecture
* **AI Engine (Text Analysis):** Utilizes **Logistic Regression** and **TF-IDF** vectorization, trained on a dataset of 82,000+ emails, to calculate precise threat probabilities.
* **Vision Module (Anti-Quishing):** Integrates **OpenCV** to scan image/PDF attachments, locate QR position markers, and extract hidden malicious URLs for AI scanning.
* **Forensics & Integration:** Generates local SHA-256 hashes of attachments and queries the **VirusTotal API** for file reputation. Uses flat JSON files instead of heavy SQL databases for maximum speed.
* **Live Threat Dashboard:** Real-time data visualization and forensic PDF report generation built entirely in Python using **Streamlit**.

## ⚙️ Installation & Setup

**1. Clone the repository**
`git clone https://github.com/YouniXC/OmniSecure.git`

**2. Install Dependencies**
`pip install -r requirements.txt`

**3. Download the Pre-Trained AI Models**
> ⚠️ **Important:** Due to GitHub's file size limits, the trained Machine Learning models are hosted externally.
> * Download the models here: https://drive.google.com/drive/folders/1Ydn5Nw8l6UeKmNaUtBUvKBfHKejZ2ggl?usp=sharing
> * Create a folder named `models` inside the main project directory.
> * Place the downloaded `.pkl` files inside this `models` folder.

**4. Desktop Placement**
For the best experience and easy access, move the cloned `OmniSecure` folder directly to your Desktop.

**5. Run the Application**
To start the application, run the CustomTkinter launcher script (do **not** run `main.py` directly). Open your terminal inside the OmniSecure folder and run:
`python launcher.py`
*(Note: If your launcher file is named something else, replace `launcher.py` with your exact filename).*

## 👨‍💻 Development Team
Developed as a Final Year Capstone Project for a BS in Cybersecurity at Sindh Madressatul Islam University (SMIU).
* **Muhammad Younus** - Lead Developer & AI Specialist 
* **Hifazat Ali** - UI/UX & Documentation
* **Mohsin Ali Rajper** - Integration & Testing
