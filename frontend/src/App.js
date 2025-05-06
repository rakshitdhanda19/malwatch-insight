// src/App.js
import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './pages/Login';
import Register from './pages/Register';
import UserDashboard from './pages/UserDashboard';
import AdminDashboard from './pages/AdminDashboard';
import ScanResults from './pages/ScanResults';
import Layout from './components/Layout';
import AuthLoader from './components/AuthLoader';

function App() {
  return (
    <AuthProvider>
      <Routes>
        {/* Public routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

      
            {/* Admin-only route */}
            <Route path="/admin" element={
              <ProtectedRoute allowedRoles={['admin']}>
                <AdminDashboard />
              </ProtectedRoute>
            } />

              {/* Protected routes with layout */}
        <Route element={<Layout />}>
          <Route element={<AuthLoader />}>

            {/* User routes */}
            <Route path="/" element={
              <ProtectedRoute allowedRoles={['user', 'admin']}>
                <UserDashboard />
              </ProtectedRoute>
            } />
            <Route path="/scan-results" element={
              <ProtectedRoute allowedRoles={['user', 'admin']}>
                <ScanResults />
              </ProtectedRoute>
            } />
          </Route>
        </Route>

        {/* Redirect to login for unknown routes */}
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </AuthProvider>
  );
}

export default App;