from flask import Flask, render_template, request, send_file, Response, jsonify
import Network_Traffic_and_Anomly_Detection as detection
import time
import logging
import json

app = Flask(__name__)
logging.basicConfig(filename='logs/app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize the set of blocked IPs
blocked_ips = set()

# Route to render index.html with interfaces selection
@app.route('/')
def index():
    interfaces = detection.get_interfaces()
    return render_template('index.html', interfaces=interfaces)

@app.route('/detect', methods=['POST'])
def detect():
    interface = request.form['interface']
    packet_count = 1000

    # Capture packets
    packets = detection.capture_packets(interface, packet_count)

    # Extract features
    features = detection.extract_features(packets)

    # Train model (if needed)
    model = detection.train_model(features)

    # Detect anomalies
    anomalies = detection.detect_anomalies(model, features, packets)

    # Generate and save visualizations
    detection.plot_packet_length_distribution(features)
    detection.plot_protocol_distribution(features)
    detection.plot_time_series_packet_length(packets)
    detection.visualize_anomalies(features, anomalies)

    # Prepare anomalies for display in the template
    formatted_anomalies = []
    for anomaly in anomalies:
        from_ip, to_ip = anomaly.split(" --> ")
        formatted_anomalies.append((from_ip, to_ip))

    # Return detection results or redirect to results page
    return render_template('result.html', interface=interface, formatted_anomalies=formatted_anomalies)

# Route to serve static plot images
@app.route('/plot/<plot_name>')
def plot(plot_name):
    plot_path = f'static/{plot_name}.png'
    return send_file(plot_path, mimetype='image/png')

# Route to render the dashboard
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/block_ip', methods=['POST'])
def block_ip():
    global blocked_ips  # Access the global blocked_ips set
    data = request.get_json()
    ip_to_block = data.get('ip')

    if ip_to_block:
        blocked_ips.add(ip_to_block)
        return jsonify({'message': f'IP {ip_to_block} blocked successfully'}), 200
    else:
        return jsonify({'error': 'Invalid request'}), 400

# Route to stream live traffic for a specific interface
@app.route('/traffic/<interface>')
def traffic(interface):
    def generate():
        while True:
            # Capture packets
            packets = detection.capture_packets(interface, 1000)
            for packet in packets:
                yield str(packet) + '\n'
            time.sleep(1)  # Adjust sleep time as needed

    return Response(generate(), content_type='text/plain')

if __name__ == '__main__':
    app.run(debug=True, port=8000)
