import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [authState, setAuthState] = useState({
    isAuthenticated: false,
    isAdmin: false,
    username: '',
    isLoading: true,
  });

  const navigate = useNavigate();

  // Axios configuration
  axios.defaults.withCredentials = true;
  axios.defaults.baseURL = 'http://localhost:5000';
  // Remove the global Content-Type setting as it breaks file uploads
  // axios.defaults.headers.common['Content-Type'] = 'application/json';

  // Request interceptor to attach token
  useEffect(() => {
    const requestInterceptor = axios.interceptors.request.use(config => {
      const token = localStorage.getItem('token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    }, error => {
      return Promise.reject(error);
    });

    return () => {
      axios.interceptors.request.eject(requestInterceptor);
    };
  }, []);

  // Response interceptor to handle 401 errors
  useEffect(() => {
    const responseInterceptor = axios.interceptors.response.use(
      response => response,
      error => {
        if (error.response?.status === 401) {
          handleLogout();
        }
        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.response.eject(responseInterceptor);
    };
  }, [navigate]);

  // Add this useEffect to verify token on component mount
  useEffect(() => {
    verifyToken();
  }, []);

  // Token verification function
  const verifyToken = async () => {
    const token = localStorage.getItem('token');
    if (!token) {
      setAuthState(prev => ({ ...prev, isLoading: false }));
      return false;
    }

    try {
      const response = await axios.get('/verify-token', {
        headers: {
          'Authorization': `Bearer ${token}`
        },
        validateStatus: (status) => status < 500 // Don't throw on 4xx errors
      });

      if (response.status === 200 && response.data?.user) {
        setAuthState({
          isAuthenticated: true,
          isAdmin: Boolean(response.data.user.is_admin),
          username: response.data.user.username,
          isLoading: false
        });
        return true;
      }

      // If verification failed
      throw new Error(response.data?.error || 'Token verification failed');
    } catch (error) {
      console.error('Token verification error:', error.message);
      handleLogout();
      return false;
    }
  };

  const handleLogout = useCallback(() => {
    localStorage.removeItem('token');
    setAuthState({
      isAuthenticated: false,
      isAdmin: false,
      username: '',
      isLoading: false,
    });
    navigate('/login');
  }, [navigate]);

  const login = async (username, password) => {
    try {
      const response = await axios.post('/login', { username, password });
      const token = response.data.access_token;
      
      // Verify token structure
      const payload = JSON.parse(atob(token.split('.')[1]));
      if (typeof payload.sub !== 'string') {
        throw new Error('Invalid token format: subject must be string');
      }
  
      localStorage.setItem('token', token);
      
      setAuthState({
        isAuthenticated: true,
        isAdmin: response.data.isAdmin,
        username: response.data.username,
        isLoading: false
      });
  
      navigate(response.data.isAdmin ? '/admin' : '/');
      
      return { success: true };
    } catch (error) {
      console.error('Login failed:', error);
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Login failed' 
      };
    }
  };

  const register = async (username, email, password) => {
    try {
      const response = await axios.post('/register', {
        username,
        email,
        password,
      });
      
      return { 
        success: response.data.success,
        message: response.data.message 
      };
    } catch (error) {
      console.error('Registration error:', error);
      return {
        success: false,
        error: error.response?.data?.error || 'Registration failed',
      };
    }
  };

  const value = {
    authState,
    isAuthenticated: authState.isAuthenticated,
    isAdmin: authState.isAdmin,
    username: authState.username,
    isLoading: authState.isLoading,
    login,  // Make sure this is included
    logout :handleLogout,
    register,
    // Don't expose setAuthState directly - it's an implementation detail
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}