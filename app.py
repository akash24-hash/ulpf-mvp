from flask import Flask, request, jsonify, render_template, send_file
import os
import json
import pandas as pd
from log_parser import process_logs

app = Flask(__name__)
os.makedirs('output', exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_logs():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    raw_text = file.read().decode('utf-8')
    lines = raw_text.split('\n')

    # Process logs through the pipeline
    records, duplicate_count = process_logs(lines)
    
    # Calculate Dashboard Statistics
    df = pd.DataFrame(records)
    if df.empty:
        return jsonify({"error": "No valid logs parsed"}), 400

    total_records = len(df)
    parsed_records = len(df[df['parse_status'] == 'ok'])
    unmapped_records = len(df[df['parse_status'] == 'unmapped'])
    unique_ips = df['src_ip'].replace("", pd.NA).dropna().nunique()
    anomalies = len(df[df['anomaly'] == True])
    
    # Write JSONL export
    export_path = os.path.join('output', 'normalized_events.jsonl')
    df.to_json(export_path, orient='records', lines=True)

    # Prepare chart data
    top_ips = df['src_ip'].replace("", pd.NA).dropna().value_counts().head(5).to_dict()
    time_series = df['timestamp'].str[:16].value_counts().sort_index().to_dict() # Group by minute

    return jsonify({
        "stats": {
            "total": total_records,
            "parsed": parsed_records,
            "unmapped": unmapped_records,
            "duplicates": duplicate_count,
            "unique_ips": unique_ips,
            "anomalies": anomalies
        },
        "charts": {
            "top_ips": top_ips,
            "time_series": time_series
        },
        "records": records[:100] # Return top 100 for UI table
    })

@app.route('/export')
def export_logs():
    return send_file(os.path.join('output', 'normalized_events.jsonl'), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)