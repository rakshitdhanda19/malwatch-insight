-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 07, 2025 at 03:28 PM
-- Server version: 10.4.27-MariaDB
-- PHP Version: 8.2.0

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `malwatch_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `malware_signatures`
--

CREATE TABLE `malware_signatures` (
  `id` int(11) NOT NULL,
  `signature` varchar(255) NOT NULL,
  `malware_name` varchar(100) NOT NULL,
  `malware_type` enum('Trojan','Ransomware','Spyware','Worm') NOT NULL,
  `added_by` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `scans`
--

CREATE TABLE `scans` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `filename` varchar(255) NOT NULL,
  `file_path` varchar(255) NOT NULL,
  `file_size` bigint(20) NOT NULL,
  `file_type` varchar(50) NOT NULL,
  `is_malicious` tinyint(1) NOT NULL,
  `confidence` DOUBLE DEFAULT NULL,
  `ml_model` varchar(50) NOT NULL DEFAULT 'RandomForest',
  `scan_details` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`scan_details`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `scans`
--

INSERT INTO `scans` (`id`, `user_id`, `filename`, `file_path`, `file_size`, `file_type`, `is_malicious`, `confidence`, `ml_model`, `scan_details`, `created_at`) VALUES
(1, 1, 'document.pdf', '/uploads/doc_123.pdf', 254123, 'PDF', 0, 0.12, 'RandomForest', NULL, '2025-05-03 19:05:31'),
(2, 2, 'invoice.exe', '/uploads/inv_456.exe', 1852369, 'EXE', 1, 0.98, 'RandomForest', NULL, '2025-05-03 19:05:31');

-- --------------------------------------------------------

--
-- Table structure for table `system_settings`
--

CREATE TABLE `system_settings` (
  `id` int(11) NOT NULL,
  `setting_key` varchar(50) NOT NULL,
  `setting_value` text NOT NULL,
  `description` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `system_settings`
--

INSERT INTO `system_settings` (`id`, `setting_key`, `setting_value`, `description`) VALUES
(1, 'MAX_FILE_SIZE', '10485760', 'Maximum upload file size in bytes (10MB)'),
(2, 'ALLOWED_FILE_TYPES', 'exe,dll,pdf,docx,zip', 'Comma-separated allowed extensions');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) NOT NULL,
  `is_admin` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_login` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `email`, `is_admin`, `created_at`, `last_login`) VALUES
(1, 'admin', '$2b$12$9kS6kvUk/mBVhYbNn2JFueHMnSQpXYCKCFrCPZdG0jVlZCK14dRUi', 'admin@malwatch.com', 1, '2025-05-03 19:05:31', NULL),
(2, 'user1', '$2b$12$9kS6kvUk/mBVhYbNn2JFueHMnSQpXYCKCFrCPZdG0jVlZCK14dRUi', 'user1@example.com', 0, '2025-05-03 19:05:31', NULL),
(3, 'rakshit', '$2b$12$VuQsGTzBft6.t8iuzLDf6eoRwLAL2JZQp3nSuIUWr0kz9QHA6aP6q', 'rakshit@gmail.com', 0, '2025-05-04 12:28:26', NULL),
(4, 'sidra', '$2b$12$hR/XMWNMWA.jlCEOWHRfreTuXwGF1aqaZe5rFPZoWoig7eXWX5q4.', 'sidrahanif054@gmail.com', 0, '2025-05-05 06:54:03', NULL),
(5, 'ismaeel', '$2b$12$6VrfdddiJgEymVOY/Wdlvu2feaUdvTC0qDQp8bef7Ba3e4vS7lbKe', 'ismaeel@gmail.com', 0, '2025-05-05 12:33:05', NULL),
(6, 'kinza', '$2b$12$VQE7KF66e.M7G3ZfGYh4eOcym96/VJlQ/BOmpS0IG/Lmxk0qbrQRa', 'kinza@gmail.com', 0, '2025-05-05 13:29:03', NULL),
(7, 'hello', '$2b$12$QBr0cEU./RIiYRrXIxw4qeJH1zdXeLU0OuJqnEamTqWoP01UI/UKW', 'hello@gmail.com', 0, '2025-05-05 14:12:19', NULL),
(8, 'usama', '$2b$12$/o1YWL6p0a8BNzi1Gr5PSuAPYWs64Hr83h3NdU3KlvLcvcPjR7JHy', 'usama@gmail.com', 0, '2025-05-06 12:14:30', NULL);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `malware_signatures`
--
ALTER TABLE `malware_signatures`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `signature` (`signature`),
  ADD KEY `added_by` (`added_by`);

--
-- Indexes for table `scans`
--
ALTER TABLE `scans`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `system_settings`
--
ALTER TABLE `system_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `setting_key` (`setting_key`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `malware_signatures`
--
ALTER TABLE `malware_signatures`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `scans`
--
ALTER TABLE `scans`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `system_settings`
--
ALTER TABLE `system_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `malware_signatures`
--
ALTER TABLE `malware_signatures`
  ADD CONSTRAINT `malware_signatures_ibfk_1` FOREIGN KEY (`added_by`) REFERENCES `users` (`id`);

--
-- Constraints for table `scans`
--
ALTER TABLE `scans`
  ADD CONSTRAINT `scans_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
