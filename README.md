# IoT IDS Multi-Class Analyzer

A Streamlit-based web application for analyzing IoT network traffic and detecting various types of attacks using machine learning.

## Features

- Upload and analyze IoT network data
- Detect multiple types of attacks:
  - Benign Traffic
  - DoS Flood
  - DDoS Flood
  - Recon Flood
  - MQTT Flood
- Visualize attack distributions using interactive pie charts
- Calculate prediction accuracy with labeled datasets
- Get attack descriptions and recommendations

## Setup

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Place your trained model file (`without_layer_model.pkl`) in the root directory

3. Run the Streamlit app:
```bash
streamlit run app.py
```

## Usage

1. **For Prediction Only:**
   - Upload a CSV file containing network features (without labels)
   - Click "Predict Attacks" to get predictions
   - View the results and attack distribution chart

2. **For Accuracy Calculation:**
   - Upload a CSV file containing network features and an "Attack Name" column
   - Click "Predict & Calculate Accuracy" to get predictions and accuracy metrics
   - View the comparison between true and predicted labels

## Input Data Format

- For prediction only: CSV file with feature columns
- For accuracy calculation: CSV file with feature columns and an "Attack Name" column
- The "Attack Name" column should contain one of these values:
  - Benign Traffic
  - DoS Flood
  - DDoS Flood
  - Recon Flood
  - MQTT Flood 