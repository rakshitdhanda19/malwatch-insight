import React, { useState } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import {
  Box,
  Typography,
  TextField,
  Button,
  CircularProgress,
  Paper,
  Alert,
  Grid,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  Input,
  Chip
} from '@mui/material';
import { Send, Warning, CheckCircle } from '@mui/icons-material';

function SpamDetection() {
  const { authState } = useAuth();
  const [formData, setFormData] = useState({
    subject: '',
    content: '',
    sender: ''
  });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.content.trim()) {
      setError('Email content is required');
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      const response = await axios.post('/detect-spam', formData);
      setResult(response.data);
    } catch (err) {
      console.error('Spam detection error:', err);
      setError(err.response?.data?.error || 'Failed to process email');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setFormData({
      subject: '',
      content: '',
      sender: ''
    });
    setResult(null);
    setError('');
  };

  return (
    <Box sx={{ my: 4 }}>
      <Typography variant="h5" gutterBottom>
        Spam Email Detection
      </Typography>
      
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}
      
      {result ? (
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Analysis Results
            </Typography>
            
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <Typography variant="subtitle1" sx={{ mr: 2 }}>
                Classification:
              </Typography>
              <Chip 
                icon={result.is_spam ? <Warning /> : <CheckCircle />}
                label={result.classification}
                color={result.is_spam ? 'error' : 'success'}
                variant="outlined"
              />
            </Box>
            
            <Typography variant="body1" gutterBottom>
              Confidence: {Math.round(result.confidence * 100)}%
            </Typography>
            
            <Box sx={{ mt: 3 }}>
              <Button 
                variant="contained" 
                color="primary" 
                onClick={handleReset}
              >
                Check Another Email
              </Button>
            </Box>
          </CardContent>
        </Card>
      ) : (
        <Paper sx={{ p: 3 }}>
          <form onSubmit={handleSubmit}>
            <Grid container spacing={3}>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="Sender Email"
                  name="sender"
                  value={formData.sender}
                  onChange={handleChange}
                  placeholder="example@domain.com"
                />
              </Grid>
              
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="Subject"
                  name="subject"
                  value={formData.subject}
                  onChange={handleChange}
                  placeholder="Email subject"
                />
              </Grid>
              
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  multiline
                  rows={6}
                  label="Email Content"
                  name="content"
                  value={formData.content}
                  onChange={handleChange}
                  placeholder="Paste the email content here..."
                  required
                />
              </Grid>
              
              <Grid item xs={12}>
                <Button
                  type="submit"
                  variant="contained"
                  color="primary"
                  disabled={loading || !formData.content.trim()}
                  startIcon={loading ? <CircularProgress size={20} /> : <Send />}
                >
                  {loading ? 'Analyzing...' : 'Check for Spam'}
                </Button>
              </Grid>
            </Grid>
          </form>
        </Paper>
      )}
    </Box>
  );
}

export default SpamDetection; 