import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  Box,
  Typography,
  Container,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  CircularProgress,
  Alert,
  Card,
  CardContent,
  Grid
} from '@mui/material';
import { Logout, CloudUpload, History } from '@mui/icons-material';

function UserDashboard() {
  const { authState, logout } = useAuth();
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);

  // Fetch user's scan history
  // Add this useEffect to verify token structure
useEffect(() => {
  const verifyTokenStructure = () => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (typeof payload.sub !== 'string') {
          console.error('Invalid token structure - logging out');
          logout();
          navigate('/login');
        }
      } catch (e) {
        console.error('Token parsing error:', e);
        logout();
        navigate('/login');
      }
    }
  };

  verifyTokenStructure();
}, [logout, navigate]);

// Update your data fetching
const fetchScans = async () => {
  try {
    setLoading(true);
    const token = localStorage.getItem('token');
    
    if (!token) {
      throw new Error('No authentication token found');
    }

    // Verify token structure
    const payload = JSON.parse(atob(token.split('.')[1]));
    if (typeof payload.sub !== 'string') {
      throw new Error('Invalid token structure');
    }

    const response = await axios.get('/scans', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    setScans(response.data.scans || []);
  } catch (err) {
    console.error('Error fetching scans:', err);
    setError(err.response?.data?.error || 'Failed to load scan history');
    
    if (err.response?.status === 401 || err.message.includes('token')) {
      logout();
      navigate('/login');
    }
  } finally {
    setLoading(false);
  }
};

  // Handle file upload
  const handleFileUpload = async (e) => {
  e.preventDefault();

  if (!file) {
    setError('Please select a file first');
    return;
  }

  setUploading(true);
  setError('');

  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await axios.post('/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    });

   if (!response.data || response.data.error) {
  throw new Error(response.data?.error || 'Upload failed');
}

    // Separate try-catch for fetchScans
    try {
      await fetchScans();
    } catch (fetchError) {
      console.error('Failed to fetch scans:', fetchError);
      setError('Scan list update failed after upload');
    }

    navigate(`/scan-result/${response.data.scan_id}`);
  } catch (err) {
    console.error('Upload process error:', err);
    setError(err.response?.data?.error ||
             err.response?.data?.details ||
             err.message ||
             'File upload failed');
  } finally {
    setUploading(false);
  }
};

  // const handleFileUpload = async (e) => {
  //   e.preventDefault();
    
  //   if (!file) {
  //     setError('Please select a file first');
  //     return;
  //   }
  
  //   setUploading(true);
  //   setError('');
  
  //   const formData = new FormData();
  //   formData.append('file', file);
  
  //   try {
  //     const response = await axios.post('/upload', formData, {
  //       headers: {
  //         'Content-Type': 'multipart/form-data',
  //         'Authorization': `Bearer ${localStorage.getItem('token')}`
  //       }
  //     });
  
  //     if (response.data.success) {
  //       await fetchScans(); // Refresh the scan list
  //       navigate(`/scan-result/${response.data.scan_id}`);
  //     } else {
  //       throw new Error(response.data.error || 'sacns Upload failed');
  //     }
  //   } catch (err) {
  //     console.error('Upload error:', err);
  //     setError(err.response?.data?.error || 
  //              err.response?.data?.details || 
  //              err.message || 
  //              'File upload failed');
  //   } finally {
  //     setUploading(false);
  //   }
  // };

  // Initial data load
  useEffect(() => {
    fetchScans();
  }, []);

  // Redirect if not authenticated
  useEffect(() => {
    if (!authState.isLoading && !authState.isAuthenticated) {
      navigate('/login');
    }
  }, [authState, navigate]);

  return (
    <Container maxWidth="lg">
      <Box sx={{ my: 4 }}>
        {/* Header Section */}
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
          <Typography variant="h4" component="h1">
            User Dashboard
          </Typography>
          <Button
            variant="contained"
            color="error"
            startIcon={<Logout />}
            onClick={logout}
          >
            Logout
          </Button>
        </Box>

        {/* Welcome Message */}
        <Paper sx={{ p: 3, mb: 4 }}>
          <Typography variant="h6" gutterBottom>
            Welcome, {authState.username}
          </Typography>
          <Typography variant="body1">
            Upload files for malware scanning and view your scan history below.
          </Typography>
        </Paper>

        {/* Error Alert */}
        {error && (
          <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        {/* Upload Section */}
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Upload File for Scanning
            </Typography>
            <form onSubmit={handleFileUpload}>
              <Grid container spacing={2} alignItems="center">
                <Grid item xs={12} sm={8}>

                  <label htmlFor="file-upload">
                    <Button
                      variant="outlined"
                      component="span"
                      fullWidth
                      startIcon={<CloudUpload />}
                    >
                      {file ? file.name : 'Select File'}
                    </Button>
                  </label>
                  <input
  type="file"
  id="file-upload"
  onChange={(e) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  }}
  style={{ display: 'none' }}
  accept=".exe,.dll,.pdf,.docx,.zip"
/>
                </Grid>
                <Grid item xs={12} sm={4}>
                  <Button
                    type="submit"
                    variant="contained"
                    color="primary"
                    fullWidth
                    disabled={!file || uploading}
                    startIcon={uploading ? <CircularProgress size={20} /> : null}
                  >
                    {uploading ? 'Scanning...' : 'Scan File'}
                  </Button>
                </Grid>
              </Grid>
            </form>
          </CardContent>
        </Card>

        {/* Scan History Section */}
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Your Scan History
            </Typography>
            {loading ? (
              <Box display="flex" justifyContent="center" py={4}>
                <CircularProgress />
              </Box>
            ) : scans.length === 0 ? (
              <Typography variant="body1" color="text.secondary">
                No scan history available
              </Typography>
            ) : (
              <TableContainer component={Paper}>
                <Table>
                 <TableHead>
  <TableRow>
    <TableCell>Filename</TableCell>
    <TableCell>Result</TableCell>
    <TableCell>Malware Type</TableCell>
    <TableCell>Prediction</TableCell>
    <TableCell>Date</TableCell>
    <TableCell>Actions</TableCell>
  </TableRow>
</TableHead>
                 <TableBody>
  {scans.map((scan) => (
    <TableRow key={scan.id}>
      <TableCell>{scan.filename}</TableCell>
      <TableCell>
        <Box
          component="span"
          sx={{
            color: scan.is_malicious ? 'error.main' : 'success.main',
            fontWeight: 'bold'
          }}
        >
          {scan.is_malicious ? 'Malicious' : 'Clean'}
        </Box>
      </TableCell>
      <TableCell>{scan.malware_type || 'N/A'}</TableCell>
      <TableCell>
        {typeof scan.confidence === 'number'
          ? `${(scan.confidence * 100).toFixed(1)}%`
          : 'N/A'}
      </TableCell>
      <TableCell>
        {new Date(scan.created_at).toLocaleString()}
      </TableCell>
      <TableCell>
        <Button
          size="small"
          onClick={() => navigate(`/scan-result/${scan.id}`)}
          startIcon={<History />}
        >
          Details
        </Button>
      </TableCell>
    </TableRow>
  ))}
</TableBody>

                </Table>
              </TableContainer>
            )}
          </CardContent>
        </Card>
      </Box>
    </Container>
  );
}

export default UserDashboard;