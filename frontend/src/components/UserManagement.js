import React, { useState, useEffect } from 'react';

function UserManagement() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = () => {
    setLoading(true);
    fetch('/api/admin/users')
      .then((response) => response.json())
      .then((data) => {
        setUsers(data);
        setLoading(false);
      })
      .catch((error) => {
        console.error('Error fetching users:', error);
        setError(error);
        setLoading(false);
      });
  };

  const handleDelete = (userId) => {
    if (!window.confirm('Are you sure you want to delete this user?')) return;

    fetch(`/api/admin/users/${userId}`, {
      method: 'DELETE',
    })
      .then((response) => {
        if (response.ok) {
          setUsers(users.filter((user) => user.id !== userId));
        } else {
          console.error('Failed to delete user');
        }
      })
      .catch((error) => console.error('Error deleting user:', error));
  };

  const handlePromote = (userId) => {
    fetch(`/api/admin/users/${userId}/promote`, {
      method: 'PUT',
    })
      .then((response) => {
        if (response.ok) {
          fetchUsers(); // Refresh list to show updated admin status
        } else {
          console.error('Failed to promote user');
        }
      })
      .catch((error) => console.error('Error promoting user:', error));
  };

  return (
    <div className="user-management">
      <h2>User Management</h2>

      {loading && <p>Loading users...</p>}
      {error && <p style={{ color: 'red' }}>Error loading users: {error.message}</p>}

      {!loading && (
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Admin</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td>{user.username}</td>
                <td>{user.email}</td>
                <td>{user.is_admin ? 'Yes' : 'No'}</td>
                <td>
                  <button onClick={() => handleDelete(user.id)}>Delete</button>
                  {!user.is_admin && (
                    <button onClick={() => handlePromote(user.id)}>Promote to Admin</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default UserManagement;
