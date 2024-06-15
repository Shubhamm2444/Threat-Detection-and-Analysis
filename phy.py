** Data Preprocessing (Python Code):

import pandas as pd

def preprocess_logs(log_file):
    # Read logs into a pandas DataFrame
    df = pd.read_csv(log_file)

    # Clean and format data
    df['timestamp'] = pd.to_datetime(df['timestamp'])  # Convert timestamps
    df.fillna(method='ffill', inplace=True)  # Fill missing values (optional)
    df['user_agent'] = df['user_agent'].str.lower()  # Normalize user agent

    return df

# Example usage
df = preprocess_logs('login_attempts.log')


** Feature Engineering (Python Code):

def create_features(df):
    """Calculates features for anomaly detection, like login frequency and user risk score."""
    df['login_attempts_past_hour'] = df.groupby('username')['timestamp'].transform('size', offset=pd.Timedelta(hours=-1))
    df['user_risk_score'] = calculate_user_risk_score(df)  # Replace with Expedia's risk scoring function
    return df

def calculate_user_risk_score(df):
    """Example user risk score based on recent login locations (replace with Expedia's logic)."""
    risk_score = 0
    for index, row in df.iterrows():
        # Check if login originated from a previously unknown location
        if row['is_new_location']:  # Placeholder for location comparison logic
            risk_score += 1
    return risk_score

df = create_features(df.copy())  # Operate on a copy to avoid modifying original data


** Anomaly Detection (Python Code):
Isolation Forest: Suitable for identifying outliers (suspicious logins) in high-dimensional data.
One-Class SVM: Useful when only normal data is available for training.
Custom Anomaly Detection Models: Consider Expedia's specific needs and data characteristics.

  from sklearn.ensemble import IsolationForest
# from sklearn.svm import OneClassSVM  # Optional for One-Class SVM

def detect_anomalies(df):
    """Trains an Isolation Forest model to identify suspicious login attempts."""
    model = IsolationForest(contamination=0.01)  # Adjust contamination for desired detection rate
    model.fit(df[['login_attempts_past_hour', 'user_risk_score']])
    df['anomaly_score'] = model.decision_function(df[['login_attempts_past_hour', 'user_risk_score']])
    return df

df = detect_anomalies(df)


** Alert Prioritization (Python Code):

def prioritize_alerts(df):
    """Assigns severity scores based on anomaly score, factors like IP reputation, and user risk score."""
    df['severity'] = 'Low'
    df.loc[(df['anomaly_score'] < -0.5) & (df['login_attempts_past_hour'] > 10), 'severity'] = 'Medium'
    df.loc[(df['anomaly_score'] < -0.7) & (df['is_foreign_ip'] == True) & (df['user_risk_score'] > 0.5), 'severity'] = 'High'  # Adjust conditions based on Expedia's risk factors
    return df

def is_foreign_ip(ip


** Additional Considerations:
Threat Intelligence: Incorporate threat intelligence feeds to identify suspicious IP addresses or user agents associated with known malicious activity.
Machine Learning: Explore machine learning models like Random Forest or Support Vector Machines for more sophisticated anomaly detection.
User Risk Profiling: Consider risk factors beyond IP location, such as user access.





