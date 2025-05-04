import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { 
  Box, 
  Typography, 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow, 
  Paper,
  Chip,
  CircularProgress
} from '@mui/material';
import { Warning, CheckCircle } from '@mui/icons-material';

function ScanResults() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const { user } = useAuth();

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const response = await axios.get('http://localhost:5000/scans', {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('token')}`
          }
        });
        setScans(response.data);
      } catch (error) {
        console.error('Error fetching scans:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchScans();
  }, []);

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>
        Scan History
      </Typography>

      {loading ? (
        <Box display="flex" justifyContent="center" mt={4}>
          <CircularProgress />
        </Box>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Filename</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Date</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Confidence</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scans.map((scan) => (
                <TableRow key={scan.id}>
                  <TableCell>{scan.filename}</TableCell>
                  <TableCell>{scan.file_type}</TableCell>
                  <TableCell>
                    {new Date(scan.created_at).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    {scan.is_malicious ? (
                      <Chip
                        icon={<Warning />}
                        label="Malicious"
                        color="error"
                        variant="outlined"
                      />
                    ) : (
                      <Chip
                        icon={<CheckCircle />}
                        label="Clean"
                        color="success"
                        variant="outlined"
                      />
                    )}
                  </TableCell>
                  <TableCell>
                    {scan.confidence ? `${(scan.confidence * 100).toFixed(2)}%` : 'N/A'}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {!loading && scans.length === 0 && (
        <Typography variant="body1" align="center" mt={4}>
          No scan history found
        </Typography>
      )}
    </Box>
  );
}

export default ScanResults;