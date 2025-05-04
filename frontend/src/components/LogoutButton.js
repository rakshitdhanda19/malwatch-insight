import React from 'react';
import { useAuth } from '../context/AuthContext';
import { Button } from '@mui/material';

export default function LogoutButton() {
  const { logout } = useAuth();
  
  return (
    <Button 
      color="inherit"
      onClick={logout}
    >
      Logout
    </Button>
  );
}