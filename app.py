import streamlit as st
import pandas as pd
import joblib


# Load Model & Feature List


model = joblib.load("ids_rf_important_features.pkl")
important_features = joblib.load("important_features.pkl")

st.set_page_config(page_title="Intrusion Detection System", layout="centered")

st.title("🛡️ Smart Intrusion Detection System")
st.markdown("Detect whether network traffic is **Normal** or an **Attack** using machine learning.")

st.markdown("---")

st.subheader("🔧 Network Traffic Parameters")




# Input Sliders (With Realistic Ranges)


src_bytes = st.slider("Source Bytes", 0, 100000, 500)
dst_bytes = st.slider("Destination Bytes", 0, 100000, 500)
count = st.slider("Connection Count", 0, 500, 5)
srv_count = st.slider("Service Count", 0, 500, 5)

serror_rate = st.slider("Serror Rate", 0.0, 1.0, 0.0)
srv_serror_rate = st.slider("Service Serror Rate", 0.0, 1.0, 0.0)

rerror_rate = st.slider("Rerror Rate", 0.0, 1.0, 0.0)
srv_rerror_rate = st.slider("Service Rerror Rate", 0.0, 1.0, 0.0)

same_srv_rate = st.slider("Same Service Rate", 0.0, 1.0, 0.5)

dst_host_count = st.slider("Destination Host Count", 0, 255, 10)
dst_host_srv_count = st.slider("Destination Host Service Count", 0, 255, 10)

dst_host_serror_rate = st.slider("Destination Host Serror Rate", 0.0, 1.0, 0.0)
dst_host_srv_serror_rate = st.slider("Destination Host Service Serror Rate", 0.0, 1.0, 0.0)

st.markdown("---")


# Prepare Input


input_data = {
    "src_bytes": src_bytes,
    "dst_bytes": dst_bytes,
    "count": count,
    "srv_count": srv_count,
    "serror_rate": serror_rate,
    "srv_serror_rate": srv_serror_rate,
    "same_srv_rate": same_srv_rate,
    "dst_host_count": dst_host_count,
    "dst_host_srv_count": dst_host_srv_count,
    "dst_host_serror_rate": dst_host_serror_rate,
    "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
    "rerror_rate": rerror_rate,
    "srv_rerror_rate": srv_rerror_rate
}

input_df = pd.DataFrame([input_data])


# Prediction


import plotly.graph_objects as go

if st.button("🚀 Detect Intrusion"):

    prediction = model.predict(input_df)[0]
    attack_probability = model.predict_proba(input_df)[0][0]  # 0 = Attack

    st.subheader("🔍 Detection Result")

    if prediction == 1:
        st.success("✅ Normal Traffic Detected")
    else:
        st.error("🚨 Attack Detected!")

    st.write(f"### Attack Probability: {attack_probability:.2%}")


    # Risk Meter Gauge
    

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=attack_probability * 100,
        title={'text': "Attack Risk Level (%)"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "black"},
            'steps': [
                {'range': [0, 40], 'color': "green"},
                {'range': [40, 70], 'color': "orange"},
                {'range': [70, 100], 'color': "red"}
            ],
        }
    ))

    st.plotly_chart(fig, use_container_width=True)

import numpy as np
import time
import plotly.graph_objects as go

st.markdown("---")
st.header("📊 Live IDS Security Dashboard")

run_dashboard = st.checkbox("Start Live Monitoring Dashboard")

if run_dashboard:

    # Initialize counters
    total_packets = 0
    attack_count = 0
    normal_count = 0

    attack_history = []
    packet_log = []

    dashboard_placeholder = st.empty()

    for i in range(50):

        # Simulated network packet
        simulated_data = {
            "src_bytes": np.random.randint(0, 50000),
            "dst_bytes": np.random.randint(0, 50000),
            "count": np.random.randint(0, 200),
            "srv_count": np.random.randint(0, 200),
            "serror_rate": np.random.uniform(0, 1),
            "srv_serror_rate": np.random.uniform(0, 1),
            "same_srv_rate": np.random.uniform(0, 1),
            "dst_host_count": np.random.randint(0, 255),
            "dst_host_srv_count": np.random.randint(0, 255),
            "dst_host_serror_rate": np.random.uniform(0, 1),
            "dst_host_srv_serror_rate": np.random.uniform(0, 1),
            "rerror_rate": np.random.uniform(0, 1),
            "srv_rerror_rate": np.random.uniform(0, 1)
        }

        sim_df = pd.DataFrame([simulated_data])

        prediction = model.predict(sim_df)[0]
        attack_prob = model.predict_proba(sim_df)[0][0] * 100

        # Update counters
        total_packets += 1

        if prediction == 0:
            attack_count += 1
            status = "Attack"
        else:
            normal_count += 1
            status = "Normal"

        attack_rate = (attack_count / total_packets) * 100

        attack_history.append(attack_rate)

        packet_log.append({
            "Packet #": total_packets,
            "Status": status,
            "Attack Probability (%)": round(attack_prob, 2)
        })

        with dashboard_placeholder.container():

            
            # KPI CARDS
            
            col1, col2, col3, col4 = st.columns(4)

            col1.metric("Total Packets", total_packets)
            col2.metric("Attacks Detected", attack_count)
            col3.metric("Normal Traffic", normal_count)
            col4.metric("Attack Rate (%)", f"{attack_rate:.2f}")

            st.markdown("---")

            
            # Risk Gauge
            
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=attack_prob,
                title={'text': "Current Packet Risk (%)"},
                gauge={
                    'axis': {'range': [0, 100]},
                    'steps': [
                        {'range': [0, 40], 'color': "green"},
                        {'range': [40, 70], 'color': "orange"},
                        {'range': [70, 100], 'color': "red"}
                    ],
                }
            ))

            st.plotly_chart(fig_gauge, use_container_width=True)

            
            # Live Attack Trend
            
            fig_trend = go.Figure()
            fig_trend.add_trace(go.Scatter(
                y=attack_history,
                mode='lines',
                name='Attack Rate (%)'
            ))
            fig_trend.update_layout(title="Live Attack Rate Trend")

            st.plotly_chart(fig_trend, use_container_width=True)

            
            # Attack Log
            
            st.subheader("📜 Traffic Log")
            st.dataframe(pd.DataFrame(packet_log).tail(10))

        time.sleep(1)
