// // import React, { useState, useEffect } from 'react';
// // import { useAuth } from '../context/AuthContext';
// // import axios from 'axios';
// // import { 
// //   Box, 
// //   Typography, 
// //   Container,
// //   Paper,
// //   Table,
// //   TableBody,
// //   TableCell,
// //   TableContainer,
// //   TableHead,
// //   TableRow,
// //   Button,
// //   CircularProgress,
// //   Alert,
// //   Tabs,
// //   Tab
// // } from '@mui/material';
// // import { useNavigate } from 'react-router-dom';

// // function AdminDashboard() {
 
// //   const { authState , logout} = useAuth();
// //   const [users, setUsers] = useState([]);
// //   const [scans, setScans] = useState([]);
// //   const [loading, setLoading] = useState(true);
// //   const [error, setError] = useState('');
// //   const [tabValue, setTabValue] = useState(0);
// //   const navigate = useNavigate();

// //   useEffect(() => {
// //     console.log('Current authState:', authState);
  
// //   if (!authState.isLoading && !authState.isAuthenticated) {
// //     navigate('/login');
// //     return;
// //   }
// //   if (!authState.isLoading && authState.isAuthenticated && !authState.isAdmin) {
// //     navigate('/');
// //     return;
// //   }
    

// //   const fetchData = async () => {
// //     try {
// //       setLoading(true);
// //       const token = authState?.token;  // Make sure token exists
  
// //       const config = {
// //         headers: {
// //           Authorization: `Bearer ${token}`
// //         }
// //       };
  
// //       const [usersRes, scansRes] = await Promise.all([
// //         axios.get('http://localhost:5000/admin/users', config),
// //         axios.get('http://localhost:5000/admin/scans', config)
// //       ]);
  
// //       setUsers(usersRes.data.users);
// //       setScans(scansRes.data.scans);
// //     } catch (err) {
// //       console.error('Fetch error:', err);
// //       setError(err.response?.data?.error || 'Failed to load data');
// //     } finally {
// //       setLoading(false);
// //     }
// //   };
  

// //     fetchData();
// //   }, [authState, navigate]);

// //   const handleDeleteUser = async (userId) => {
// //     if (!window.confirm('Are you sure you want to delete this user?')) return;
    
// //     try {
// //       await axios.delete(`http://localhost:5000/admin/users/${userId}`);
// //       setUsers(users.filter(user => user.id !== userId));
// //     } catch (err) {
// //       console.error('Delete error:', err);
// //       setError(err.response?.data?.error || 'Failed to delete user');
// //     }
// //   };

// //   const handleTabChange = (event, newValue) => {
// //     setTabValue(newValue);
// //   };

// //   const handleLogout = () => {
// //     logout();
// //     navigate('/login');
// //   };

// //   if (loading) {
// //     return (
// //       <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
// //         <CircularProgress size={60} />
// //       </Box>
// //     );
// //   }

// //   return (
// //     <Container maxWidth="lg">
// //       <Box sx={{ my: 4 }}>
// //         <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
// //           <Typography variant="h4" component="h1">
// //             Admin Dashboard
// //           </Typography>
// //           <Button 
// //             variant="contained" 
// //             color="error"
// //             onClick={handleLogout}
// //           >
// //             Logout
// //           </Button>
// //         </Box>

// //         {error && (
// //           <Alert severity="error" sx={{ mb: 3 }}>
// //             {error}
// //           </Alert>
// //         )}

// //         <Paper sx={{ p: 2, mb: 3 }}>
// //           <Typography variant="h6" gutterBottom>
// //             Welcome, {authState.username}
// //           </Typography>
// //           <Typography variant="body1">
// //             You have administrator privileges.
// //           </Typography>
// //         </Paper>

// //         <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
// //           <Tabs value={tabValue} onChange={handleTabChange}>
// //             <Tab label="User Management" />
// //             <Tab label="Scan History" />
// //           </Tabs>
// //         </Box>

// //         {tabValue === 0 && (
// //           <TableContainer component={Paper} sx={{ mt: 2 }}>
// //             <Table>
// //               <TableHead>
// //                 <TableRow>
// //                   <TableCell>ID</TableCell>
// //                   <TableCell>Username</TableCell>
// //                   <TableCell>Email</TableCell>
// //                   <TableCell>Admin</TableCell>
// //                   <TableCell>Joined</TableCell>
// //                   <TableCell>Actions</TableCell>
// //                 </TableRow>
// //               </TableHead>
// //               <TableBody>
// //                 {users.map((user) => (
// //                   <TableRow key={user.id}>
// //                     <TableCell>{user.id}</TableCell>
// //                     <TableCell>{user.username}</TableCell>
// //                     <TableCell>{user.email}</TableCell>
// //                     <TableCell>{user.is_admin ? 'Yes' : 'No'}</TableCell>
// //                     <TableCell>
// //                       {new Date(user.created_at).toLocaleDateString()}
// //                     </TableCell>
// //                     <TableCell>
// //                       <Button 
// //                         size="small" 
// //                         color="error"
// //                         onClick={() => handleDeleteUser(user.id)}
// //                         disabled={user.id === authState.id}
// //                       >
// //                         Delete
// //                       </Button>
// //                     </TableCell>
// //                   </TableRow>
// //                 ))}
// //               </TableBody>
// //             </Table>
// //           </TableContainer>
// //         )}

// //         {tabValue === 1 && (
// //           <TableContainer component={Paper} sx={{ mt: 2 }}>
// //             <Table>
// //               <TableHead>
// //                 <TableRow>
// //                   <TableCell>ID</TableCell>
// //                   <TableCell>User</TableCell>
// //                   <TableCell>Filename</TableCell>
// //                   <TableCell>Result</TableCell>
// //                   <TableCell>Date</TableCell>
// //                 </TableRow>
// //               </TableHead>
// //               <TableBody>
// //                 {scans.map((scan) => (
// //                   <TableRow key={scan.id}>
// //                     <TableCell>{scan.id}</TableCell>
// //                     <TableCell>{scan.username}</TableCell>
// //                     <TableCell>{scan.filename}</TableCell>
// //                     <TableCell>
// //                       <span style={{ 
// //                         color: scan.is_malicious ? 'red' : 'green',
// //                         fontWeight: 'bold'
// //                       }}>
// //                         {scan.is_malicious ? 'Malicious' : 'Clean'}
// //                       </span>
// //                       {scan.confidence && (
// //                         <span style={{ marginLeft: '8px', color: '#666' }}>
// //                           ({Math.round(scan.confidence * 100)}%)
// //                         </span>
// //                       )}
// //                     </TableCell>
// //                     <TableCell>
// //                       {new Date(scan.created_at).toLocaleString()}
// //                     </TableCell>
// //                   </TableRow>
// //                 ))}
// //               </TableBody>
// //             </Table>
// //           </TableContainer>
// //         )}
// //       </Box>
// //     </Container>
// //   );
// // }

// // export default AdminDashboard;
// import React, { useState, useEffect } from 'react';
// import { useAuth } from '../context/AuthContext';
// import { 
//   Box, 
//   Typography, 
//   Container,
//   Paper,
//   Table,
//   TableBody,
//   TableCell,
//   TableContainer,
//   TableHead,
//   TableRow,
//   Button,
//   CircularProgress,
//   Alert,
//   Tabs,
//   Tab
// } from '@mui/material';
// import { useNavigate } from 'react-router-dom';
// import axios from 'axios';

// function AdminDashboard() {
//   const { authState, logout } = useAuth();
//   const [users, setUsers] = useState([]);
//   const [scans, setScans] = useState([]);
//   const [loading, setLoading] = useState(true);
//   const [error, setError] = useState('');
//   const [tabValue, setTabValue] = useState(0);
//   const navigate = useNavigate();

//   const fetchData = async () => {
//     if (!authState.isAdmin) return;
  
//     try {
//       setLoading(true);
//       setError('');
  
//       // Ensure your Flask endpoint URL is correct
//       const baseURL = 'http://localhost:5000'; // Flask default port
      
//       const config = {
//         headers: {
//           'Authorization': `Bearer ${authState.token}`,
//           'Content-Type': 'application/json'
//         },
//         withCredentials: true // If using cookies
//       };
  
//       const [usersRes, scansRes] = await Promise.all([
//         axios.get(`${baseURL}/admin/users`, config),
//         axios.get(`${baseURL}/admin/scans`, config)
//       ]);
  
//       // Handle responses
//       if (usersRes.data.error) {
//         throw new Error(usersRes.data.error);
//       }
//       if (scansRes.data.error) {
//         throw new Error(scansRes.data.error);
//       }
  
//       setUsers(usersRes.data.users);
//       setScans(scansRes.data.scans);
  
//     } catch (err) {
//       console.error('API Error:', {
//         message: err.message,
//         response: err.response?.data
//       });
//       setError(err.response?.data?.error || err.message);
//     } finally {
//       setLoading(false);
//     }
//   };

//   useEffect(() => {
//     if (!authState.isLoading && !authState.isAdmin) {
//       navigate('/');
//     }
//   }, [authState, navigate]);

//   useEffect(() => {
//     if (authState.isAuthenticated && authState.isAdmin) {
//       fetchData();
//     }
//   }, [authState.isAuthenticated, authState.isAdmin]);

//   const handleDeleteUser = async (userId) => {
//     if (!window.confirm('Are you sure you want to delete this user?')) return;
    
//     try {
//       await axios.delete(`/admin/users/${userId}`);
//       setUsers(users.filter(user => user.id !== userId));
//     } catch (err) {
//       console.error('Delete error:', err);
//       setError(err.response?.data?.error || 'Failed to delete user');
//     }
//   };

//   const handleTabChange = (event, newValue) => {
//     setTabValue(newValue);
//   };

//   const handleLogout = () => {
//     logout();
//     navigate('/login');
//   };

//   if (loading) {
//     return (
//       <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
//         <CircularProgress size={60} />
//       </Box>
//     );
//   }

//   return (
//     <Container maxWidth="lg">
//       <Box sx={{ my: 4 }}>
//         <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
//           <Typography variant="h4" component="h1">
//             Admin Dashboard
//           </Typography>
//           <Button 
//             variant="contained" 
//             color="error"
//             onClick={handleLogout}
//           >
//             Logout
//           </Button>
//         </Box>

//         {error && (
//           <Alert severity="error" sx={{ mb: 3 }}>
//             {error}
//           </Alert>
//         )}

//         <Paper sx={{ p: 2, mb: 3 }}>
//           <Typography variant="h6" gutterBottom>
//             Welcome, {authState.username}
//           </Typography>
//           <Typography variant="body1">
//             You have administrator privileges.
//           </Typography>
//         </Paper>

//         <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
//           <Tabs value={tabValue} onChange={handleTabChange}>
//             <Tab label="User Management" />
//             <Tab label="Scan History" />
//           </Tabs>
//         </Box>

//         {tabValue === 0 && (
//           <TableContainer component={Paper} sx={{ mt: 2 }}>
//             <Table>
//               <TableHead>
//                 <TableRow>
//                   <TableCell>ID</TableCell>
//                   <TableCell>Username</TableCell>
//                   <TableCell>Email</TableCell>
//                   <TableCell>Admin</TableCell>
//                   <TableCell>Joined</TableCell>
//                   <TableCell>Actions</TableCell>
//                 </TableRow>
//               </TableHead>
//               <TableBody>
//                 {users.map((user) => (
//                   <TableRow key={user.id}>
//                     <TableCell>{user.id}</TableCell>
//                     <TableCell>{user.username}</TableCell>
//                     <TableCell>{user.email}</TableCell>
//                     <TableCell>{user.is_admin ? 'Yes' : 'No'}</TableCell>
//                     <TableCell>
//                       {new Date(user.created_at).toLocaleDateString()}
//                     </TableCell>
//                     <TableCell>
//                       <Button 
//                         size="small" 
//                         color="error"
//                         onClick={() => handleDeleteUser(user.id)}
//                         disabled={user.id === authState.id}
//                       >
//                         Delete
//                       </Button>
//                     </TableCell>
//                   </TableRow>
//                 ))}
//               </TableBody>
//             </Table>
//           </TableContainer>
//         )}

//         {tabValue === 1 && (
//           <TableContainer component={Paper} sx={{ mt: 2 }}>
//             <Table>
//               <TableHead>
//                 <TableRow>
//                   <TableCell>ID</TableCell>
//                   <TableCell>User</TableCell>
//                   <TableCell>Filename</TableCell>
//                   <TableCell>Result</TableCell>
//                   <TableCell>Confidence</TableCell>
//                   <TableCell>Date</TableCell>
//                 </TableRow>
//               </TableHead>
//               <TableBody>
//                 {scans.map((scan) => (
//                   <TableRow key={scan.id}>
//                     <TableCell>{scan.id}</TableCell>
//                     <TableCell>{scan.username}</TableCell>
//                     <TableCell>{scan.filename}</TableCell>
//                     <TableCell>
//                       <span style={{ 
//                         color: scan.is_malicious ? 'red' : 'green',
//                         fontWeight: 'bold'
//                       }}>
//                         {scan.is_malicious ? 'Malicious' : 'Clean'}
//                       </span>
//                     </TableCell>
//                     <TableCell>
//                       {scan.confidence ? `${Math.round(scan.confidence * 100)}%` : 'N/A'}
//                     </TableCell>
//                     <TableCell>
//                       {new Date(scan.created_at).toLocaleString()}
//                     </TableCell>
//                   </TableRow>
//                 ))}
//               </TableBody>
//             </Table>
//           </TableContainer>
//         )}
//       </Box>
//     </Container>
//   );
// }

// export default AdminDashboard;
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
  Tabs,
  Tab,
  IconButton,
  Tooltip,
  TextField,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Snackbar
} from '@mui/material';
import {
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  Logout as LogoutIcon,
  Visibility as VisibilityIcon,
  Search as SearchIcon
} from '@mui/icons-material';

function AdminDashboard() {
  const { authState, logout } = useAuth();
  const navigate = useNavigate();
  
  // State management
  const [users, setUsers] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [tabValue, setTabValue] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [openDeleteDialog, setOpenDeleteDialog] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  
  // Fetch data function
 // In AdminDashboard.js
 const fetchData = async () => {
  try {
    setLoading(true);
    setError('');
    
    // Verify we have a valid token first
    const token = localStorage.getItem('token');
    if (!token) {
      throw new Error('Authentication token missing');
    }

    // Configure request with error handling
    const makeAuthenticatedRequest = async (url) => {
      try {
        const response = await axios.get(url, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          validateStatus: (status) => status < 500
        });

        if (response.status === 422) {
          throw new Error(response.data?.error || 'Data validation failed');
        }
        if (response.status !== 200) {
          throw new Error(response.data?.error || `Request failed with status ${response.status}`);
        }
        return response.data;
      } catch (error) {
        console.error(`Request to ${url} failed:`, error);
        throw error;
      }
    };

    // Make parallel requests with better error handling
    const [usersData, scansData] = await Promise.allSettled([
      makeAuthenticatedRequest('/admin/users'),
      makeAuthenticatedRequest('/admin/scans')
    ]);

    // Handle results
    if (usersData.status === 'rejected') {
      throw new Error(`Users: ${usersData.reason.message}`);
    }
    if (scansData.status === 'rejected') {
      throw new Error(`Scans: ${scansData.reason.message}`);
    }

    setUsers(usersData.value.users || []);
    setScans(scansData.value.scans || []);
    
  } catch (error) {
    console.error('Data fetch error:', error);
    setError(error.message);
    
    // Handle specific error cases
    if (error.message.includes('Authentication') || 
        error.message.includes('token') ||
        error.response?.status === 401) {
      logout();
      navigate('/login');
    }
  } finally {
    setLoading(false);
  }
};
  // Initial load and auth check
  useEffect(() => {
    if (!authState.isLoading && !authState.isAdmin) {
      navigate('/');
    } else if (authState.isAuthenticated && authState.isAdmin) {
      fetchData();
    }
  }, [authState, navigate]);

  // Filter data based on search term
  const filteredUsers = users.filter(user =>
    user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
    user.email.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredScans = scans.filter(scan =>
    scan.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
    scan.filename.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Handle user deletion
  const handleDeleteUser = async () => {
    try {
      await axios.delete(`/admin/users/${selectedUser.id}`);
      setUsers(users.filter(user => user.id !== selectedUser.id));
      setSuccess('User deleted successfully');
      setOpenDeleteDialog(false);
    } catch (err) {
      console.error('Delete error:', err);
      setError(err.response?.data?.error || 'Failed to delete user');
    }
  };

  // View scan details
  const viewScanDetails = (scan) => {
    navigate(`/scan-details/${scan.id}`);
  };

  // Tab change handler
  const handleTabChange = (event, newValue) => {
    setTabValue(newValue);
    setSearchTerm(''); // Reset search when changing tabs
  };

  if (loading && users.length === 0 && scans.length === 0) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Container maxWidth="xl">
      {/* Header Section */}
      <Box sx={{ my: 4 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
          <Typography variant="h4" component="h1">
            Admin Dashboard
          </Typography>
          <Box>
            <Tooltip title="Refresh Data">
              <IconButton onClick={fetchData} color="primary" sx={{ mr: 2 }}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>
            <Button
              variant="contained"
              color="error"
              startIcon={<LogoutIcon />}
              onClick={logout}
            >
              Logout
            </Button>
          </Box>
        </Box>

        {/* Status Alerts */}
        {error && (
          <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError('')}>
            {error}
          </Alert>
        )}
        {success && (
          <Alert severity="success" sx={{ mb: 3 }} onClose={() => setSuccess('')}>
            {success}
          </Alert>
        )}

        {/* Welcome Panel */}
        <Paper sx={{ p: 2, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            Welcome, {authState.username}
          </Typography>
          <Typography variant="body1">
            You have administrator privileges. Manage users and view scan results below.
          </Typography>
        </Paper>

        {/* Search Bar */}
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <TextField
            fullWidth
            variant="outlined"
            placeholder={`Search ${tabValue === 0 ? 'users' : 'scans'}...`}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            InputProps={{
              startAdornment: <SearchIcon color="action" sx={{ mr: 1 }} />
            }}
          />
        </Box>

        {/* Tabs */}
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={tabValue} onChange={handleTabChange}>
            <Tab label="User Management" />
            <Tab label="Scan History" />
          </Tabs>
        </Box>

        {/* User Management Tab */}
        {tabValue === 0 && (
          <TableContainer component={Paper} sx={{ mt: 2 }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>ID</TableCell>
                  <TableCell>Username</TableCell>
                  <TableCell>Email</TableCell>
                  <TableCell>Admin</TableCell>
                  <TableCell>Joined</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredUsers.length > 0 ? (
                  filteredUsers.map((user) => (
                    <TableRow key={user.id} hover>
                      <TableCell>{user.id}</TableCell>
                      <TableCell>{user.username}</TableCell>
                      <TableCell>{user.email}</TableCell>
                      <TableCell>{user.is_admin ? 'Yes' : 'No'}</TableCell>
                      <TableCell>
                        {new Date(user.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        <Tooltip title="Delete User">
                          <IconButton
                            color="error"
                            onClick={() => {
                              setSelectedUser(user);
                              setOpenDeleteDialog(true);
                            }}
                            disabled={user.id === authState.id}
                          >
                            <DeleteIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={6} align="center">
                      No users found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {/* Scan History Tab */}
        {tabValue === 1 && (
          <TableContainer component={Paper} sx={{ mt: 2 }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>ID</TableCell>
                  <TableCell>User</TableCell>
                  <TableCell>Filename</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Result</TableCell>
                  <TableCell>Confidence</TableCell>
                  <TableCell>Date</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredScans.length > 0 ? (
                  filteredScans.map((scan) => (
                    <TableRow key={scan.id} hover>
                      <TableCell>{scan.id}</TableCell>
                      <TableCell>{scan.username}</TableCell>
                      <TableCell>{scan.filename}</TableCell>
                      <TableCell>{scan.file_type}</TableCell>
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
                      <TableCell>
                        {scan.confidence ? `${Math.round(scan.confidence * 100)}%` : 'N/A'}
                      </TableCell>
                      <TableCell>
                        {new Date(scan.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <Tooltip title="View Details">
                          <IconButton
                            color="primary"
                            onClick={() => viewScanDetails(scan)}
                          >
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={8} align="center">
                      No scans found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Box>

      {/* Delete User Dialog */}
      <Dialog
        open={openDeleteDialog}
        onClose={() => setOpenDeleteDialog(false)}
      >
        <DialogTitle>Confirm Deletion</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete user <strong>{selectedUser?.username}</strong>?
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDeleteDialog(false)}>Cancel</Button>
          <Button
            onClick={handleDeleteUser}
            color="error"
            variant="contained"
            startIcon={<DeleteIcon />}
          >
            Delete User
          </Button>
        </DialogActions>
      </Dialog>

      {/* Success Snackbar */}
      <Snackbar
        open={!!success}
        autoHideDuration={6000}
        onClose={() => setSuccess('')}
        message={success}
      />
    </Container>
  );
}

export default AdminDashboard;