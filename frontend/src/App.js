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
import SpamDetection from './components/SpamDetection';

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
            <Route path="/scan-result/:id" element={
              <ProtectedRoute allowedRoles={['user', 'admin']}>
                <ScanResults />
              </ProtectedRoute>
            } />
            {/* Spam Detection route */}
            <Route path="/spam-detection" element={
              <ProtectedRoute allowedRoles={['user', 'admin']}>
                <SpamDetection />
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