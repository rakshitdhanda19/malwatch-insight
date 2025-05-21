// AdminScans.js

import React, { useState, useEffect } from 'react';

function AdminScans() {
  const [scans, setScans] = useState([]);

  useEffect(() => {
    // Fetch all scans from backend API
    fetch('/api/admin/scans')
      .then((response) => response.json())
      .then((data) => setScans(data))
      .catch((error) => console.error('Error fetching admin scans:', error));
  }, []);

  return (
    <div className="admin-scans">
      <h2>All Scans</h2>
      <table>
        <thead>
          <tr>
            <th>Username</th>
            <th>Filename</th>
            <th>Malware Type</th>
            <th>Malicious</th>
            <th>Confidence</th>
            <th>Date</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan_results) => (
            <tr key={scan.id}>
              <td>{scan_results.username}</td>
              <td>{scan_results.filename}</td>
              <td>{scan_results.malware_type}</td>
              <td>{scan_results.is_malicious ? 'Yes' : 'No'}</td>
              <td>{scan_results.confidence}</td>
              <td>{new Date(scan_results.created_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default AdminScans;
