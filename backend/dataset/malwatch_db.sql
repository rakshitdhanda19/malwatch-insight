-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 19, 2025 at 10:42 AM
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
  `confidence` float DEFAULT NULL,
  `ml_model` varchar(50) NOT NULL DEFAULT 'RandomForest',
  `scan_details` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`scan_details`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `scans`
--

INSERT INTO `scans` (`id`, `user_id`, `filename`, `file_path`, `file_size`, `file_type`, `is_malicious`, `confidence`, `ml_model`, `scan_details`, `created_at`) VALUES
(1, 1, 'document.pdf', '/uploads/doc_123.pdf', 254123, 'PDF', 0, 0.12, 'RandomForest', NULL, '2025-05-03 19:05:31'),
(3, 5, '25-200-000253.pdf', 'uploads\\25-200-000253.pdf', 0, '', 1, 0.960671, 'RandomForest', NULL, '2025-05-14 21:10:13'),
(4, 5, '25-200-000253.pdf', 'uploads\\25-200-000253.pdf', 0, '', 1, 0.960671, 'RandomForest', NULL, '2025-05-14 21:10:25'),
(5, 5, 'usman_variety.pdf', 'uploads\\usman_variety.pdf', 0, '', 1, 0.960671, 'RandomForest', NULL, '2025-05-14 21:10:37'),
(6, 5, 'Lab_8.docx', 'uploads\\Lab_8.docx', 0, '', 1, 0.960671, 'RandomForest', NULL, '2025-05-14 21:10:59'),
(7, 3, 'Evading_IDS.docx', 'uploads\\Evading_IDS.docx', 0, '', 1, 0.960671, 'RandomForest', NULL, '2025-05-14 22:16:08'),
(8, 4, 'Malwatch_Insight_Design_Overview.docx', 'uploads\\Malwatch_Insight_Design_Overview.docx', 0, '', 0, 0, 'RandomForest', NULL, '2025-05-17 12:07:38'),
(9, 4, 'Design_2.pdf', 'uploads\\Design_2.pdf', 0, '', 0, 0, 'RandomForest', NULL, '2025-05-17 12:07:51'),
(10, 4, '25-200-000276.pdf', 'uploads\\25-200-000276.pdf', 0, '', 0, 0, 'RandomForest', NULL, '2025-05-17 12:08:02');

-- --------------------------------------------------------

--
-- Table structure for table `scan_results`
--

CREATE TABLE `scan_results` (
  `id` int(11) NOT NULL,
  `filename` varchar(255) NOT NULL,
  `result` varchar(100) NOT NULL,
  `confidence` float NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `malware_type` varchar(100) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `scan_results`
--

INSERT INTO `scan_results` (`id`, `filename`, `result`, `confidence`, `created_at`, `malware_type`, `user_id`) VALUES
(1, 'Install.exe', '2', 0.37, '2025-05-18 19:18:40', NULL, NULL),
(2, 'Install.exe', '2', 0.37, '2025-05-18 19:18:47', NULL, NULL),
(3, 'AI_Suggestions_for_Task_A.pdf', '2', 0.26, '2025-05-18 19:19:34', NULL, NULL),
(4, 'AI_Suggestions_for_Task_A.pdf', '2', 0.26, '2025-05-18 19:19:35', NULL, NULL),
(5, 'AI_Suggestions_for_Task_A.pdf', '2', 0.26, '2025-05-18 19:20:42', NULL, NULL),
(6, 'Install.exe', '2', 0.37, '2025-05-18 19:21:07', NULL, NULL),
(7, 'part2assembly.pdf', '2', 0.26, '2025-05-18 19:25:57', NULL, NULL),
(8, 'assembly.pdf', '2', 0.26, '2025-05-18 19:32:37', NULL, NULL),
(9, 'A1_Template_V5-2025.docx', '2', 0.25, '2025-05-19 05:08:04', NULL, NULL),
(10, 'A1_Template_V5-2025.docx', '2', 0.25, '2025-05-19 05:17:26', NULL, NULL),
(11, 'Assigment.docx', '2', 0.25, '2025-05-19 05:24:20', NULL, NULL),
(12, 'Assigment.docx', '2', 0.25, '2025-05-19 05:24:22', NULL, NULL),
(13, 'part2assembly.pdf', '2', 0.26, '2025-05-19 05:30:04', NULL, NULL),
(14, 'LinkedIn_Carousel.pdf', '2', 0.27, '2025-05-19 05:36:22', NULL, NULL),
(15, 'LinkedIn_Carousel.pdf', '2', 0.27, '2025-05-19 05:39:32', NULL, NULL),
(16, 'Assigment.docx', '2', 0.25, '2025-05-19 05:39:47', NULL, NULL),
(17, 'Assigment.docx', '2', 0.25, '2025-05-19 05:39:49', NULL, NULL),
(18, 'assignment-1_rubric_v4-2025.pdf', '2', 0.23, '2025-05-19 05:40:18', NULL, NULL),
(19, 'Assignment-1_Notes_v2-2025.pdf', '2', 0.26, '2025-05-19 05:47:53', NULL, NULL),
(20, 'Assignment-1_Notes_v2-2025.pdf', '2', 0.26, '2025-05-19 05:48:01', NULL, NULL),
(21, 'Assignment-1_Notes_v2-2025.pdf', '2', 0.26, '2025-05-19 05:48:10', NULL, NULL),
(22, 'Install.exe', '2', 0.37, '2025-05-19 05:48:19', NULL, NULL),
(23, 'Install.exe', '2', 0.37, '2025-05-19 05:48:53', NULL, NULL),
(24, 'LinkedIn_Carousel.pdf', '2', 0.27, '2025-05-19 05:49:27', NULL, NULL),
(25, 'python.pdf', '2', 0.26, '2025-05-19 05:55:59', NULL, NULL),
(26, 'python.pdf', '2', 0.26, '2025-05-19 05:56:24', NULL, NULL),
(27, 'task_ssl.pdf', '2', 0.26, '2025-05-19 05:57:27', NULL, NULL),
(28, 'task_ssl.pdf', '2', 0.26, '2025-05-19 06:09:57', NULL, NULL),
(29, 'task_ssl.pdf', '2', 0.26, '2025-05-19 06:11:18', NULL, NULL),
(30, 'task_ssl.pdf', 'Error', 0, '2025-05-19 06:23:24', 'Error', 7),
(31, 'task_ssl.pdf', 'Error', 0, '2025-05-19 06:28:16', 'Error', 7),
(32, 'task_ssl.pdf', 'Error', 0, '2025-05-19 06:28:47', 'Error', 7),
(33, 'task_ssl.pdf', 'Error', 0, '2025-05-19 06:31:42', 'Error', 7),
(34, 'task_ssl.pdf', 'Error', 0, '2025-05-19 06:32:44', 'Error', 7),
(35, 'Intro_to_machine_learning.docx', 'Error', 0, '2025-05-19 06:34:45', 'Error', 7),
(36, 'Intro_to_machine_learning.docx', 'Error', 0, '2025-05-19 06:36:46', 'Error', 7),
(37, 'house_prediction.pdf', 'Error', 0, '2025-05-19 06:37:34', 'Error', 7),
(38, 'house_prediction_report.docx', 'Error', 0, '2025-05-19 06:40:56', 'Error', 7),
(39, 'house_prediction_report.docx', 'Error', 0, '2025-05-19 06:43:39', 'Error', 7),
(40, 'house_prediction_report.docx', 'Error', 0, '2025-05-19 06:44:47', 'Error', 7),
(41, 'house_prediction_report.docx', 'Error', 0, '2025-05-19 06:45:35', 'Error', 7),
(42, 'ques.docx', 'Error', 0, '2025-05-19 06:45:50', 'Error', 7);

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
-- Indexes for table `scan_results`
--
ALTER TABLE `scan_results`
  ADD PRIMARY KEY (`id`);

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
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `scan_results`
--
ALTER TABLE `scan_results`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=43;

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
