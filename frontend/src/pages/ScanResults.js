import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  Box,
  Typography,
  Container,
  Paper,
  Button,
  CircularProgress,
  Alert,
  List,
  ListItem,
  ListItemText,
  Divider,
  Chip
} from '@mui/material';
import { ArrowBack } from '@mui/icons-material';

function ScanResult() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchScanDetails = async () => {
      try {
        setLoading(true);
        const response = await axios.get(`/scans/${id}`);
        setScan(response.data.scan);
      } catch (err) {
        console.error('Error fetching scan details:', err);
        setError(err.response?.data?.error || 'Failed to load scan details');
      } finally {
        setLoading(false);
      }
    };

    fetchScanDetails();
  }, [id]);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Container maxWidth="md">
      <Box sx={{ my: 4 }}>
        <Button
          variant="outlined"
          onClick={() => navigate(-1)}
          startIcon={<ArrowBack />}
          sx={{ mb: 3 }}
        >
          Back to Dashboard
        </Button>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {scan && (
          <Paper sx={{ p: 3 }}>
            <Typography variant="h4" gutterBottom>
              Scan Results: {scan.filename}
            </Typography>
            <Divider sx={{ my: 2 }} />

            <List>
              <ListItem>
                <ListItemText
                  primary="Scan Status"
                  secondary={
                    <Chip
                      label={scan.is_malicious ? 'Malicious' : 'Clean'}
                      color={scan.is_malicious ? 'error' : 'success'}
                      variant="outlined"
                    />
                  }
                />
              </ListItem>
              {scan.confidence && (
                <ListItem>
                  <ListItemText
                    primary="Confidence Level"
                    secondary={`${Math.round(scan.confidence * 100)}%`}
                  />
                </ListItem>
              )}
              <ListItem>
                <ListItemText
                  primary="File Type"
                  secondary={scan.file_type || 'Unknown'}
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="File Size"
                  secondary={`${(scan.file_size / 1024).toFixed(2)} KB`}
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="Scan Date"
                  secondary={new Date(scan.created_at).toLocaleString()}
                />
              </ListItem>
            </List>

            <Divider sx={{ my: 2 }} />
            <Typography variant="h6" gutterBottom>
              Analysis Details
            </Typography>
            <Typography variant="body1">
              {scan.analysis_details || 'No additional details available.'}
            </Typography>
          </Paper>
        )}
      </Box>
    </Container>
  );
}

export default ScanResult;