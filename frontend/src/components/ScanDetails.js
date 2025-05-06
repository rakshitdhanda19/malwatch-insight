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
import { ArrowBack as ArrowBackIcon } from '@mui/icons-material';

function ScanDetails() {
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
        <CircularProgress size={60} />
      </Box>
    );
  }

  if (error) {
    return (
      <Container maxWidth="md" sx={{ mt: 4 }}>
        <Alert severity="error">{error}</Alert>
        <Button
          variant="contained"
          sx={{ mt: 2 }}
          onClick={() => navigate(-1)}
          startIcon={<ArrowBackIcon />}
        >
          Back to Dashboard
        </Button>
      </Container>
    );
  }

  if (!scan) {
    return (
      <Container maxWidth="md" sx={{ mt: 4 }}>
        <Alert severity="warning">Scan not found</Alert>
        <Button
          variant="contained"
          sx={{ mt: 2 }}
          onClick={() => navigate(-1)}
          startIcon={<ArrowBackIcon />}
        >
          Back to Dashboard
        </Button>
      </Container>
    );
  }

  return (
    <Container maxWidth="md">
      <Box sx={{ my: 4 }}>
        <Button
          variant="outlined"
          onClick={() => navigate(-1)}
          startIcon={<ArrowBackIcon />}
          sx={{ mb: 3 }}
        >
          Back to Dashboard
        </Button>

        <Typography variant="h4" gutterBottom>
          Scan Details
        </Typography>

        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            {scan.filename}
          </Typography>
          <Divider sx={{ my: 2 }} />

          <List>
            <ListItem>
              <ListItemText
                primary="User"
                secondary={scan.username || 'Unknown'}
              />
            </ListItem>
            <ListItem>
              <ListItemText
                primary="Upload Date"
                secondary={new Date(scan.created_at).toLocaleString()}
              />
            </ListItem>
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
                primary="Status"
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
          </List>

          <Divider sx={{ my: 2 }} />
          <Typography variant="body1">
            <strong>Analysis Details:</strong> {scan.analysis_details || 'No additional details available.'}
          </Typography>
        </Paper>
      </Box>
    </Container>
  );
}

export default ScanDetails;