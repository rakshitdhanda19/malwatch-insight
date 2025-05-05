// src/App.js
import React from 'react';
import { Routes, Route } from 'react-router-dom';
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
  console.log("App rendering");

  return (
    <AuthProvider> {/* ✅ Now properly placed INSIDE BrowserRouter */}
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* Protected layout & routes */}
        <Route element={<Layout />}>
          <Route element={<AuthLoader />}>
            <Route element={<ProtectedRoute allowedRoles={['user', 'admin']} />}>
              <Route path="/" element={<UserDashboard />} />
              <Route path="/scan-results" element={<ScanResults />} />
            </Route>
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
