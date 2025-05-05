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
            <th>File Type</th>
            <th>Malicious</th>
            <th>Confidence</th>
            <th>Date</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td>{scan.username}</td>
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

export default AdminScans;
