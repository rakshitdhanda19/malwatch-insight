import React from 'react';
import AdminScans from '../components/AdminScans';
import UserManagement from '../components/UserManagement';

function AdminDashboard() {
  return (
    <div className="admin-dashboard">
      <h1>Admin Dashboard</h1>
      <div className="admin-sections">
        <UserManagement />
        <AdminScans />
      </div>
    </div>
  );
}

export default AdminDashboard;