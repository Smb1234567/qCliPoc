# Next-Generation AI-Based Anomaly Detection System for Authentication Logs

This cutting-edge system detects suspicious user access patterns from authentication/authorization logs using advanced machine learning, behavioral biometrics, and federated learning techniques.

## Revolutionary Features
- **Log ingestion and processing** - Support for multiple log formats (syslog, JSON, CSV, Apache)
- **User behavior profiling** - Comprehensive behavioral baselines for each user
- **Multi-layered anomaly detection** - Statistical, ML, graph-based, and deep learning methods
- **Behavioral biometric analysis** - Keystroke dynamics and mouse movement analysis
- **Real-time streaming analytics** - Sliding window processing for live anomaly detection
- **Explainable AI (XAI)** - SHAP and LIME-based explanations for detected anomalies
- **Federated learning** - Privacy-preserving collaborative model training across organizations
- **Advanced visualization** - Interactive dashboard with detailed analytics
- **Adaptive alerting** - Context-aware alert generation with customizable thresholds

## Innovation Highlights

### 🧠 Advanced Anomaly Detection
- **Graph Neural Networks**: Detects anomalies based on user-IP relationship patterns using NetworkX and PyTorch Geometric
- **Deep Learning**: LSTM and attention mechanisms for sequential behavioral pattern analysis
- **Ensemble Methods**: Combines multiple detection strategies for improved accuracy

### 📊 Behavioral Biometric Analysis
- **Keystroke Dynamics**: Analyzes timing patterns in keyboard input (hold times, flight times, latencies)
- **Mouse Movement Analysis**: Tracks cursor movement patterns, speed, acceleration, and click intervals
- **Biometric Profiling**: Creates unique behavioral signatures for each user

### ⚡ Real-Time Streaming Analytics
- **Sliding Windows**: Processes events in configurable time windows for real-time insights
- **Continuous Monitoring**: Detects anomalies as they happen rather than in batch mode
- **Event Processing**: Handles high-volume authentication streams efficiently

### 🔍 Explainable AI (XAI)
- **SHAP Values**: Provides feature importance for each detected anomaly
- **LIME Explanations**: Local interpretations of model decisions
- **Rule-Based Insights**: Combines ML with interpretable business rules
- **Visual Analytics**: Charts and graphs explaining anomaly patterns

### 🤝 Federated Learning
- **Privacy Preservation**: Collaborative model training without sharing raw data
- **Secure Aggregation**: Encrypted model parameter exchange between participants
- **Cross-Organization Learning**: Improves detection by learning from multiple organizations
- **Robust Security**: Cryptographic protection of model parameters

## Architecture
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Log Sources   │───▶│  Data Pipeline   │───▶│  Advanced ML    │
└─────────────────┘    └──────────────────┘    │  Models         │
                                                │ • Graph NN      │
┌─────────────────┐    ┌──────────────────┐    │ • Deep Learning │
│   Biometric     │───▶│  Real-time       │───▶│ • Ensemble      │
│   Sensors       │    │  Stream Proc.    │    └─────────────────┘
└─────────────────┘    └──────────────────┘              │
                                                          │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Federation    │───▶│  XAI Module      │───▶│  Anomaly Engine │
│   Network       │    │  (SHAP/LIME)    │    └─────────────────┘
└─────────────────┘    └──────────────────┘              │
                                                          │
┌─────────────────┐    ┌──────────────────┐              │
│   Dashboard     │◀───│  Alert System    │◀─────────────┘
└─────────────────┘    └──────────────────┘
```

## Setup
```bash
pip install -r requirements.txt
python app.py
```

## Usage

### Basic Usage
1. Place authentication logs in the `data/` directory
2. Run the system: `python app.py`
3. Access the dashboard at `http://localhost:8050`

### With Innovative Features
```bash
python app.py --innovative --log-file /path/to/logs.log
```

### Demo Mode
```bash
python app.py --demo
```

### Dashboard Mode
```bash
python app.py --dashboard
```

## Key Innovations Explained

### Graph-Based Anomaly Detection
Our system constructs dynamic graphs connecting users and IP addresses, identifying structural anomalies that traditional methods miss. This reveals coordinated attacks or compromised accounts.

### Behavioral Biometric Profiling
By analyzing keystroke patterns and mouse movements, we create unique behavioral fingerprints that are nearly impossible to replicate, providing an additional layer of authentication verification.

### Federated Threat Intelligence
Organizations can collaborate on threat detection without exposing sensitive authentication data, creating a collective defense against sophisticated attacks.

### Real-Time Decision Making
Unlike batch-processing systems, ours analyzes authentication events as they occur, enabling immediate response to emerging threats.

## Customization
The system supports custom log formats, adjustable sensitivity levels, and pluggable detection algorithms to meet specific organizational needs.