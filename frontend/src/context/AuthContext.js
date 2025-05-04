import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [authState, setAuthState] = useState({
    isAuthenticated: false,
    isAdmin: false,
    username: '',
    isLoading: true  // Added loading state to authState
  });

  const navigate = useNavigate();

  useEffect(() => {
    const verifyToken = async () => {
      const token = localStorage.getItem('token');
      if (token) {
        try {
          const response = await axios.get('http://localhost:5000/verify-token', {
            headers: { Authorization: `Bearer ${token}` }
          });
          setAuthState({
            isAuthenticated: true,
            isAdmin: response.data.user.is_admin,
            username: response.data.user.username,
            isLoading: false
          });
        } catch (error) {
          localStorage.removeItem('token');
          setAuthState(prev => ({ ...prev, isLoading: false }));
        }
      } else {
        setAuthState(prev => ({ ...prev, isLoading: false }));
      }
    };

    verifyToken();
  }, []);

  const login = async (username, password) => {
    try {
      const response = await axios.post('http://localhost:5000/login', {
        username,
        password
      });
      
      localStorage.setItem('token', response.data.access_token);
      
      setAuthState({
        isAuthenticated: true,
        isAdmin: response.data.is_admin,
        username: response.data.username,
        isLoading: false
      });
      
      return true;
    } catch (error) {
      return false;
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    setAuthState({
      isAuthenticated: false,
      isAdmin: false,
      username: '',
      isLoading: false
    });
    navigate('/login');
  };

  return (
    <AuthContext.Provider value={{ 
      authState, 
      setAuthState, // Exposing setter
      login, 
      logout 
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}