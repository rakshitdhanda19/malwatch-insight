// RecentScans.js

import React from 'react';

function RecentScans({ scans }) {
  return (
    <div className="recent-scans">
      <h2>Recent Scans</h2>
      <table>
        <thead>
          <tr>
            <th>Filename</th>
            <th>File Type</th>
            <th>Malicious</th>
            <th>Confidence</th>
            <th>Date</th>
          </tr>
        </thead>
        <tbody>
         {scanHistory.map(scan => (
  <tr key={scan.id}>
    <td>{scan.filename}</td>
    <td>{scan.is_malicious === "1" ? "Malicious" : "Benign"}</td>
    <td>{(scan.confidence * 100).toFixed(2)}%</td>
    <td>{new Date(scan.created_at).toLocaleString()}</td>
  </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default RecentScans;
