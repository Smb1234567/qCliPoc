# 🔐 Authentication Anomaly Detection System

**Yo, what's good!** This system is like your homie that watches who's logging into your digital crib and hits you with the tea if something's sus. It uses AI magic to spot weird login vibes that might be a security threat.

## 🎯 What This System Does

<div align="center">

| Feature | What It Does |
|--------|--------------|
| 📋 **Log Reading** | Grabs all kinds of log formats (syslog, JSON, CSV, Apache) |
| 👤 **Behavior Learning** | Studies how each user logs in (times, places, patterns) |
| 🚨 **Anomaly Detection** | Finds weird login stuff compared to normal patterns |
| 📢 **Alert Creation** | Flags sketchy activities (High/Medium/Low vibes) |
| 📊 **Visual Display** | Shows findings in a dashboard that's easy to vibe with |

</div>

## 🌟 Key Features

### 🧠 Smart Detection Vibes
- **Statistical Analysis**: Compares login patterns to the old data
- **Machine Learning**: Uses AI to spot complex patterns
- **Graph Analysis**: Maps connections between users and IPs to find sketchy links
- **Sequential Patterns**: Looks for unusual sequences of login events

### 📊 Behavioral Analysis
- **Time Analysis**: Checks if logins happen at weird hours
- **Location Tracking**: Monitors IP addresses and where they're from
- **Frequency Monitoring**: Watches for too many login attempts

### ⚡ Real-Time Capabilities
- **Live Monitoring**: Processes logins as they happen
- **Instant Alerts**: Sends notifications when sketchy activity pops off
- **Sliding Windows**: Analyzes recent activity patterns in real-time

### 🔍 Clear Explanations
- **Detailed Reports**: Explains why something was flagged as sus
- **Visual Dashboard**: Shows results with cool charts and graphs
- **Actionable Insights**: Helps security peeps understand what to check out

## 🚀 How to Get Started

### 1. Install the Goods
```bash
pip install -r requirements.txt
```

### 2. Try the Demo (Bestie Move First!)
```bash
python app.py --demo
```
This creates fake login data and shows you how the system works without needing real log files.

### 3. Process Real Log Files
```bash
python app.py --log-file your_log_file.log
```
This analyzes your actual authentication logs and finds suspicious activities.

### 4. View Results in Dashboard
```bash
python app.py --dashboard
```
Then open your web browser and hit up `http://localhost:8050` to see the visual tea.

### 5. Try Advanced Features (Flex Mode - Optional)
```bash
python app.py --demo --innovative
```
This uses all the advanced AI features to catch even more subtle anomalies.

## ⚠️ Important Note About Data Quality

**TBH**: The system might crash if your log files have incomplete entries (missing usernames or IP addresses).

**If you run into issues:**
1. **Use basic mode**: Run without `--innovative` flag for smooth operation
2. **Clean your data**: Make sure your log files don't have blank usernames or IPs
3. **Try demo first**: Use `--demo` to see the system working with clean sample data

## 📈 What You'll See

<div align="center">

```
--- Detection Summary ---
Total log entries processed: 100
Unique users: 10
Anomalies detected: 5
Anomalies by severity:
  High: 1
  Medium: 4
Alerts generated: 5
```

</div>

When you run the system, you'll get:
- **Summary of results**: How many log entries were processed
- **Number of anomalies found**: How many sketchy activities were detected
- **Severity breakdown**: How many were high/medium/low priority
- **Alerts**: Notifications about suspicious activities
- **Saved files**: Processed data and user profiles saved to disk

## 🆘 Need Help?

1. **Start with the demo** to understand how the system works
2. **Check your log files** to make sure they have complete info
3. **Use the dashboard** to visualize results in a chill format
4. **Refer to the sample logs** to see the expected format

**This system is fire** - start with the demo, then move to your real log files, and finally explore the dashboard for visual insights! 🔥