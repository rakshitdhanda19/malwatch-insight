import React from 'react';
import FileUpload from '../components/FileUpload';
import RecentScans from '../components/RecentScans';

function UserDashboard() {
  return (
    <div className="dashboard">
      <h1>Welcome to MalWatch</h1>
      <div className="scan-section">
        <FileUpload />
        <RecentScans />
      </div>
    </div>
  );
}

export default UserDashboard;