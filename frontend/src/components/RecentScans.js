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
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td>{scan.filename}</td>
              <td>{scan.file_type}</td>
              <td>{scan.is_malicious ? 'Yes' : 'No'}</td>
              <td>{scan.confidence}</td>
              <td>{new Date(scan.created_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default RecentScans;
