// import React, { useEffect } from 'react';
// import { useNavigate } from 'react-router-dom';
// import { useAuth } from '../context/AuthContext';
// import { CircularProgress, Box } from '@mui/material';

// export default function AuthLoader({ children }) {
//   const { loading, isAuthenticated } = useAuth(); // Assuming your context provides `loading` and `isAuthenticated`
//   const navigate = useNavigate();

//   useEffect(() => {
//     if (!loading && !isAuthenticated) {
//       // Redirect to login if not authenticated
//       navigate('/login');
//     }
//   }, [loading, isAuthenticated, navigate]);

//   if (loading) {
//     return (
//       <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
//         <CircularProgress />
//       </Box>
//     );
//   }

//   return children;
// }
import React, { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { CircularProgress, Box } from '@mui/material';

export default function AuthLoader({ children, allowedRoles = [] }) {
  const { authState } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (!authState.isLoading) {
      // If not authenticated, redirect to login with return URL
      if (!authState.isAuthenticated) {
        navigate('/login', { state: { from: location }, replace: true });
        return;
      }

      // If authenticated but not an admin trying to access admin routes
      if (!authState.isAdmin && location.pathname.startsWith('/admin')) {
        navigate('/', { replace: true });
        return;
      }

      // If admin but not on an admin route
      if (authState.isAdmin && !location.pathname.startsWith('/admin')) {
        navigate('/admin', { replace: true });
        return;
      }

      // Role-based access control
      const userRole = authState.isAdmin ? 'admin' : 'user';
      if (allowedRoles.length > 0 && !allowedRoles.includes(userRole)) {
        navigate(authState.isAdmin ? '/admin' : '/', { replace: true });
        return;
      }
    }
  }, [authState, navigate, location, allowedRoles]);

  if (authState.isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress />
      </Box>
    );
  }

  return children;
}