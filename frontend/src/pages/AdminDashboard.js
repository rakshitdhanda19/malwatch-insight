// import React, { useState, useEffect } from 'react';
// import { useAuth } from '../context/AuthContext';
// import axios from 'axios';
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

// function AdminDashboard() {
 
//   const { authState , logout} = useAuth();
//   const [users, setUsers] = useState([]);
//   const [scans, setScans] = useState([]);
//   const [loading, setLoading] = useState(true);
//   const [error, setError] = useState('');
//   const [tabValue, setTabValue] = useState(0);
//   const navigate = useNavigate();

//   useEffect(() => {
//     console.log('Current authState:', authState);
  
//   if (!authState.isLoading && !authState.isAuthenticated) {
//     navigate('/login');
//     return;
//   }
//   if (!authState.isLoading && authState.isAuthenticated && !authState.isAdmin) {
//     navigate('/');
//     return;
//   }
    

//   const fetchData = async () => {
//     try {
//       setLoading(true);
//       const token = authState?.token;  // Make sure token exists
  
//       const config = {
//         headers: {
//           Authorization: `Bearer ${token}`
//         }
//       };
  
//       const [usersRes, scansRes] = await Promise.all([
//         axios.get('http://localhost:5000/admin/users', config),
//         axios.get('http://localhost:5000/admin/scans', config)
//       ]);
  
//       setUsers(usersRes.data.users);
//       setScans(scansRes.data.scans);
//     } catch (err) {
//       console.error('Fetch error:', err);
//       setError(err.response?.data?.error || 'Failed to load data');
//     } finally {
//       setLoading(false);
//     }
//   };
  

//     fetchData();
//   }, [authState, navigate]);

//   const handleDeleteUser = async (userId) => {
//     if (!window.confirm('Are you sure you want to delete this user?')) return;
    
//     try {
//       await axios.delete(`http://localhost:5000/admin/users/${userId}`);
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
//                       {scan.confidence && (
//                         <span style={{ marginLeft: '8px', color: '#666' }}>
//                           ({Math.round(scan.confidence * 100)}%)
//                         </span>
//                       )}
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
  Tab
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

function AdminDashboard() {
  const { authState, logout } = useAuth();
  const [users, setUsers] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [tabValue, setTabValue] = useState(0);
  const navigate = useNavigate();

  const fetchData = async () => {
    if (!authState.isAdmin) return;
  
    try {
      setLoading(true);
      setError('');
  
      // Ensure your Flask endpoint URL is correct
      const baseURL = 'http://localhost:5000'; // Flask default port
      
      const config = {
        headers: {
          'Authorization': `Bearer ${authState.token}`,
          'Content-Type': 'application/json'
        },
        withCredentials: true // If using cookies
      };
  
      const [usersRes, scansRes] = await Promise.all([
        axios.get(`${baseURL}/admin/users`, config),
        axios.get(`${baseURL}/admin/scans`, config)
      ]);
  
      // Handle responses
      if (usersRes.data.error) {
        throw new Error(usersRes.data.error);
      }
      if (scansRes.data.error) {
        throw new Error(scansRes.data.error);
      }
  
      setUsers(usersRes.data.users);
      setScans(scansRes.data.scans);
  
    } catch (err) {
      console.error('API Error:', {
        message: err.message,
        response: err.response?.data
      });
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!authState.isLoading && !authState.isAdmin) {
      navigate('/');
    }
  }, [authState, navigate]);

  useEffect(() => {
    if (authState.isAuthenticated && authState.isAdmin) {
      fetchData();
    }
  }, [authState.isAuthenticated, authState.isAdmin]);

  const handleDeleteUser = async (userId) => {
    if (!window.confirm('Are you sure you want to delete this user?')) return;
    
    try {
      await axios.delete(`/admin/users/${userId}`);
      setUsers(users.filter(user => user.id !== userId));
    } catch (err) {
      console.error('Delete error:', err);
      setError(err.response?.data?.error || 'Failed to delete user');
    }
  };

  const handleTabChange = (event, newValue) => {
    setTabValue(newValue);
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Container maxWidth="lg">
      <Box sx={{ my: 4 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
          <Typography variant="h4" component="h1">
            Admin Dashboard
          </Typography>
          <Button 
            variant="contained" 
            color="error"
            onClick={handleLogout}
          >
            Logout
          </Button>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        <Paper sx={{ p: 2, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            Welcome, {authState.username}
          </Typography>
          <Typography variant="body1">
            You have administrator privileges.
          </Typography>
        </Paper>

        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={tabValue} onChange={handleTabChange}>
            <Tab label="User Management" />
            <Tab label="Scan History" />
          </Tabs>
        </Box>

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
                {users.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell>{user.id}</TableCell>
                    <TableCell>{user.username}</TableCell>
                    <TableCell>{user.email}</TableCell>
                    <TableCell>{user.is_admin ? 'Yes' : 'No'}</TableCell>
                    <TableCell>
                      {new Date(user.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <Button 
                        size="small" 
                        color="error"
                        onClick={() => handleDeleteUser(user.id)}
                        disabled={user.id === authState.id}
                      >
                        Delete
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {tabValue === 1 && (
          <TableContainer component={Paper} sx={{ mt: 2 }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>ID</TableCell>
                  <TableCell>User</TableCell>
                  <TableCell>Filename</TableCell>
                  <TableCell>Result</TableCell>
                  <TableCell>Confidence</TableCell>
                  <TableCell>Date</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {scans.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell>{scan.id}</TableCell>
                    <TableCell>{scan.username}</TableCell>
                    <TableCell>{scan.filename}</TableCell>
                    <TableCell>
                      <span style={{ 
                        color: scan.is_malicious ? 'red' : 'green',
                        fontWeight: 'bold'
                      }}>
                        {scan.is_malicious ? 'Malicious' : 'Clean'}
                      </span>
                    </TableCell>
                    <TableCell>
                      {scan.confidence ? `${Math.round(scan.confidence * 100)}%` : 'N/A'}
                    </TableCell>
                    <TableCell>
                      {new Date(scan.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Box>
    </Container>
  );
}

export default AdminDashboard;