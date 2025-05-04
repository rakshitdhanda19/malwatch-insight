// src/App.js
import React from 'react';
import { Routes, Route } from 'react-router-dom'; // Note: No BrowserRouter here
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './pages/Login';
import UserDashboard from './pages/UserDashboard';
import AdminDashboard from './pages/AdminDashboard';
import ScanResults from './pages/ScanResults';
import Layout from './components/Layout';
import AuthLoader from './components/AuthLoader';

function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        
        <Route element={<Layout />}>
          <Route element={<AuthLoader />}>
            {/* User Routes */}
            <Route element={<ProtectedRoute allowedRoles={['user', 'admin']} />}>
              <Route path="/" element={<UserDashboard />} />
              <Route path="/scan-results" element={<ScanResults />} />
            </Route>
            
            {/* Admin Routes */}
            <Route element={<ProtectedRoute allowedRoles={['admin']} />}>
              <Route path="/admin" element={<AdminDashboard />} />
            </Route>
          </Route>
        </Route>
      </Routes>
    </AuthProvider>
  );
}

export default App;