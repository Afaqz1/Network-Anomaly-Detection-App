
# Network Traffic Anomaly Detection

This project detects anomalies in network traffic using an Isolation Forest machine learning model. It captures network packets, extracts features, trains a model, and visualizes anomalies.

## Requirements

Ensure you have the following Python packages installed:

- `scapy`
- `pandas`
- `scikit-learn`
- `matplotlib`
- `psutil`
- `numpy`

Install them with:

```
python -m venv myenv
myenv\Scripts\activate.bat
pip install scapy pandas scikit-learn matplotlib psutil numpy flask
python app.py
```

#
## Configuration

- Set the `interface_name` variable to your network interface (e.g., 'Wi-Fi').

```python
interface_name = 'Wi-Fi'
```

- Set the `packet_count` variable to the number of packets to capture.

```python
packet_count = 100
```

## Output

- Prints available network interfaces.
- Displays the number of captured packets.
- Shows the number of detected anomalies and normal traffic.
- Plots a graph of the detected anomalies.
