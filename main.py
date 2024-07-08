from flask import Flask, render_template, request, send_file, Response
import detection as detection
import time
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
import pandas as pd

# Initialize Flask app
server = Flask(__name__)
app = dash.Dash(__name__, server=server)

# Flask routes (for basic pages)
@server.route('/')
def index():
    interfaces = detection.get_interfaces()
    return render_template('index.html', interfaces=interfaces)

@server.route('/detect', methods=['POST'])
def detect():
    interface = request.form['interface']
    packet_count = 100

    # Capture packets
    packets = detection.capture_packets(interface, packet_count)

    # Extract features
    features = detection.extract_features(packets)

    # Train model (if needed)
    model = detection.train_model(features)

    # Detect anomalies
    predictions = detection.detect_anomalies(model, features)

    # Generate and save visualizations (if needed)
    detection.visualize_anomalies(features, predictions)

    # Return detection results or redirect to results page
    return render_template('result.html', interface=interface, predictions=predictions)

@server.route('/plot/<plot_name>')
def plot(plot_name):
    plot_path = f'static/{plot_name}.png'
    return send_file(plot_path, mimetype='image/png')

@server.route('/traffic/<interface>')
def traffic(interface):
    def generate():
        while True:
            # Capture packets
            packets = detection.capture_packets(interface, 100)
            for packet in packets:
                yield str(packet) + '\n'
            time.sleep(1)  # Adjust sleep time as needed

    return Response(generate(), content_type='text/plain')

# Dash layout and callbacks
app.layout = html.Div([
    html.H1("Network Traffic Anomaly Detection Dashboard"),
    html.Label("Select Interface:"),
    dcc.Dropdown(
        id='interface-dropdown',
        options=[{'label': iface, 'value': iface} for iface in detection.get_interfaces().keys()],
        value=list(detection.get_interfaces().keys())[0] if detection.get_interfaces() else None
    ),
    dcc.Graph(id='anomaly-graph'),
    dcc.Interval(
        id='interval-component',
        interval=1000,  # in milliseconds
        n_intervals=0
    )
])

@app.callback(
    Output('anomaly-graph', 'figure'),
    [Input('interval-component', 'n_intervals'),
     Input('interface-dropdown', 'value')]
)
def update_anomaly_graph(n_intervals, interface):
    # Capture packets
    packets = detection.capture_packets(interface, 100)

    # Extract features
    features = detection.extract_features(packets)

    # Train model (if needed)
    model = detection.train_model(features)

    # Detect anomalies
    predictions = detection.detect_anomalies(model, features)

    # Generate and save visualizations (if needed)
    detection.visualize_anomalies(features, predictions)

    # Plot anomalies using Plotly
    features_df = pd.DataFrame(features, columns=['Packet Length', 'TTL', 'Protocol'])
    anomalies = features_df[predictions == -1]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=features_df['Packet Length'],
        y=features_df['TTL'],
        mode='markers',
        marker=dict(color='blue', size=8),
        name='Normal',
        text='Normal Traffic'
    ))
    fig.add_trace(go.Scatter(
        x=anomalies['Packet Length'],
        y=anomalies['TTL'],
        mode='markers',
        marker=dict(color='red', size=12, symbol='triangle-up'),
        name='Anomalies',
        text='Anomalies Detected'
    ))
    fig.update_layout(
        title='Network Traffic Anomalies',
        xaxis_title='Packet Length',
        yaxis_title='Time to Live (TTL)'
    )
    return fig

if __name__ == '__main__':
    server.run(debug=True)
