// context/AuthContext.js

import React, { createContext, useContext, useState, useEffect } from 'react';
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

  // Axios config
  axios.defaults.withCredentials = true;
  axios.defaults.baseURL = 'http://localhost:5000';
  axios.defaults.headers.common['Content-Type'] = 'application/json';

  // Axios response interceptor
  useEffect(() => {
    const interceptor = axios.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('token');
          setAuthState({
            isAuthenticated: false,
            isAdmin: false,
            username: '',
            isLoading: false,
          });
          navigate('/login');
        }
        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.response.eject(interceptor);
    };
  }, [navigate]);

  // Verify token on load
  useEffect(() => {
    const verifyToken = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        setAuthState((prev) => ({ ...prev, isLoading: false }));
        return;
      }

      try {
        const response = await axios.get('/verify-token', {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (response.data?.user) {
          setAuthState({
            isAuthenticated: true,
            isAdmin: response.data.user.is_admin,
            username: response.data.user.username,
            isLoading: false,
          });
        } else {
          throw new Error('Invalid user data');
        }
      } catch (error) {
        console.error('Token verification failed:', error);
        localStorage.removeItem('token');
        setAuthState({
          isAuthenticated: false,
          isAdmin: false,
          username: '',
          isLoading: false,
        });
      }
    };

    verifyToken();
  }, []);

  const login = async (username, password) => {
    try {
      const response = await axios.post('/login', { username, password });
      localStorage.setItem('token', response.data.access_token);

      setAuthState({
        isAuthenticated: true,
        isAdmin: response.data.is_admin,
        username: response.data.username,
        isLoading: false,
      });

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.error || 'Login failed',
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
      return { success: response.data.success };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.error || 'Registration failed',
      };
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    setAuthState({
      isAuthenticated: false,
      isAdmin: false,
      username: '',
      isLoading: false,
    });
    navigate('/login');
  };

  const value = {
    authState,
    setAuthState, // ✅ make sure this is accessible!
    isAuthenticated: authState.isAuthenticated,
    isAdmin: authState.isAdmin,
    username: authState.username,
    isLoading: authState.isLoading,
    login,
    logout,
    register,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}
