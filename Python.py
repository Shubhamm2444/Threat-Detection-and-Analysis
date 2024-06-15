import pandas as pd
from sklearn.ensemble import IsolationForest

# Ethical Considerations:
# - Replace placeholders with anonymized or dummy data for demonstration purposes.
# - Integrate with Expedia's existing security tools and risk scoring mechanisms.

# Sample Data (Replace with actual log data)
data = {
    'timestamp': ['2024-06-17 00:00:00', '2024-06-17 00:01:00', '2024-06-17 00:02:00', '2024-06-17 01:00:00', '2024-06-17 01:01:00', '2024-06-16 23:59:00'],
    'username': ['user1', 'user1', 'user2', 'user3', 'user1', 'user4'],
    'ip_address': ['192.168.1.1', '192.168.1.1', '10.0.0.2', '172.16.0.1', '192.168.1.2', '203.0.113.19'],  # Replace with anonymized IP addresses
    'login_result': ['Success', 'Success', 'Success', 'Success', 'Failed', 'Success'],
    'user_agent': ['Chrome on Windows', 'Chrome on Windows', 'Firefox on Linux', 'Safari on macOS', 'Chrome on Mobile', 'Edge on Windows']
}

df = pd.DataFrame(data)

# Data Preprocessing
def preprocess_logs(df):
    """Reads logs into a DataFrame, handles missing values, and normalizes user agent."""
    df['timestamp'] = pd.to_datetime(df['timestamp'])  # Convert timestamps
    df.fillna(method='ffill', inplace=True)  # Fill missing values (optional)
    df['user_agent'] = df['user_agent'].str.lower()  # Normalize user agent
    return df

df = preprocess_logs(df.copy())  # Operate on a copy to avoid modifying original data

# Feature Engineering
def create_features(df):
    """Calculates features for anomaly detection, like login frequency and placeholder risk score."""
    df['login_attempts_past_hour'] = df.groupby('username')['timestamp'].transform('size', offset=pd.Timedelta(hours=-1))
    # Replace with Expedia's user risk scoring logic
    df['user_risk_score'] = 0  # Placeholder for user risk score
    return df

df = create_features(df.copy())

# Anomaly Detection (Isolation Forest)
def detect_anomalies(df):
    """Trains an Isolation Forest model to identify suspicious login attempts."""
    model = IsolationForest(contamination=0.01)  # Adjust contamination for desired detection rate
    model.fit(df[['login_attempts_past_hour', 'user_risk_score']])
    df['anomaly_score'] = model.decision_function(df[['login_attempts_past_hour', 'user_risk_score']])
    return df

df = detect_anomalies(df)

# Alert Prioritization (Example)
def prioritize_alerts(df):
    """Assigns severity scores based on anomaly score and login attempts."""
    df['severity'] = 'Low'
    df.loc[(df['anomaly_score'] < -0.5) & (df['login_attempts_past_hour'] > 10), 'severity'] = 'Medium'
    # Replace with more comprehensive conditions based on Expedia's risk factors
    return df

df = prioritize_alerts(df)

# Example Output (Replace with integration into Expedia's security tools)
print(df[['username', 'ip_address', 'login_result', 'anomaly_score', 'severity']].to_string(index=False))


** Explanation:
Ethical Considerations: The code highlights the importance of ethical data handling and integrating with Expedia's existing security infrastructure.
Sample Data: Replace placeholders with anonymized or dummy data for demonstration purposes.
Data Preprocessing: Ensures data cleanliness and consistency.
