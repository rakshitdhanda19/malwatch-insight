import React, { useState } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';

function FileUpload() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const { user } = useAuth();

  // const handleSubmit = async (e) => {
  //   e.preventDefault();
  //   if (!file) return;

  //   setIsLoading(true);
  //   const formData = new FormData();
  //   formData.append('file', file);

  //   try {
  //     const response = await axios.post(
  //       'http://localhost:5000/upload',
  //       formData,
  //       {
  //         headers: {
  //           'Authorization': `Bearer ${localStorage.getItem('token')}`,
  //           'Content-Type': 'multipart/form-data'
  //         }
  //       }
  //     );
      
  //     // Save scan result to database
  //     await axios.post(
  //       'http://localhost:5000/scans',
  //       {
  //         filename: file.name,
  //         is_malicious: response.data.is_malicious
  //       },
  //       {
  //         headers: {
  //           'Authorization': `Bearer ${localStorage.getItem('token')}`
  //         }
  //       }
  //     );

  //     setResult(response.data);
  //   } catch (error) {
  //     console.error('Upload failed:', error);
  //   } finally {
  //     setIsLoading(false);
  //   }
  // };
const handleSubmit = async (e) => {
  e.preventDefault();
  if (!file) return;

  setIsLoading(true);
  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await axios.post(
      'http://localhost:5000/upload',
      formData,
      {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'multipart/form-data'
        }
      }
    );

    setResult(response.data);
  } catch (error) {
    console.error('Upload failed:', error.response?.data || error.message);
  } finally {
    setIsLoading(false);
  }
};

  return (
    <div className="file-upload">
      <form onSubmit={handleSubmit}>
        <input 
          type="file" 
          onChange={(e) => setFile(e.target.files[0])} 
          accept=".exe,.dll,.pdf,.docx,.zip"
        />
        <button type="submit" disabled={isLoading}>
          {isLoading ? 'Scanning...' : 'Scan File'}
        </button>
      </form>
      
      {result && (
        <div className={`result ${result.is_malicious ? 'malicious' : 'clean'}`}>
          {result.is_malicious ? '⚠️ Malicious File Detected' : '✅ File is Safe'}
        </div>
      )}
    </div>
  );
}

export default FileUpload;