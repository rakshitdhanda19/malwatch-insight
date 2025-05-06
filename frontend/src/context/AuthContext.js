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
  axios.defaults.headers.common['Content-Type'] = 'application/json';

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

  // Token verification function
  const verifyToken = useCallback(async () => {
    const token = localStorage.getItem('token');
    if (!token) {
      setAuthState(prev => ({ ...prev, isLoading: false }));
      return false;
    }

    try {
      const response = await axios.get('/verify-token', {
        validateStatus: status => status < 500 // Don't throw on 4xx errors
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
  }, []);

  // Verify token on initial load
  useEffect(() => {
    verifyToken();
  }, [verifyToken]);

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
      setAuthState(prev => ({ ...prev, isLoading: true }));
      
      const response = await axios.post('/login', { username, password });
      
      if (!response.data.access_token) {
        throw new Error('No access token received');
      }

      localStorage.setItem('token', response.data.access_token);

      // Handle both isAdmin and is_admin responses
      const isAdmin = Boolean(response.data.isAdmin ?? response.data.is_admin);
      
      setAuthState({
        isAuthenticated: true,
        isAdmin,
        username: response.data.username,
        isLoading: false
      });

      // Redirect based on role
      navigate(isAdmin ? '/admin' : '/');
      
      return { success: true };
    } catch (error) {
      console.error('Login error:', error);
      handleLogout();
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

  // const value = {
  //   authState,
  //   isAuthenticated: authState.isAuthenticated,
  //   isAdmin: authState.isAdmin,
  //   username: authState.username,
  //   isLoading: authState.isLoading,
  //   login,
  //   logout: handleLogout,
  //   register,
  //   verifyToken, // Expose for manual verification if needed
  // };
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