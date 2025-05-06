import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { CircularProgress, Box } from '@mui/material';

const ProtectedRoute = ({ children, allowedRoles }) => {
  const { authState } = useAuth();
  const location = useLocation();

  if (authState.isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress />
      </Box>
    );
  }

  if (!authState.isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

 
  // HARD redirect for admins
  if (authState.isAdmin && !location.pathname.startsWith('/admin')) {
    return <Navigate to="/admin" replace />;
  }

  // Block non-admins from admin routes
  if (!authState.isAdmin && location.pathname.startsWith('/admin')) {
    return <Navigate to="/" replace />;
  }

  const userRole = authState.isAdmin ? 'admin' : 'user';
  if (!allowedRoles.includes(userRole)) {
    return <Navigate to="/" replace />;
  }
  return children;
};

export default ProtectedRoute;