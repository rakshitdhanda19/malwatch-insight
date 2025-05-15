# Spam Detection for MalWatch Insight

This module adds email spam detection capabilities to the MalWatch Insight application.

## Features

- Text-based detection of spam emails
- Machine learning-powered classification using Naive Bayes
- User-friendly interface for checking emails
- Database tracking of all spam detection attempts
- Admin panel for model training and management

## Setup Instructions

### Prerequisites

- Python 3.7+
- MySQL database
- NLTK library
- scikit-learn

### Installation

1. Run the setup script:

```bash
python setup_spam_detection.py
```

This script will:
- Import the necessary database tables
- Train the initial spam detection model
- Verify that everything is set up correctly

### Manual Setup (if needed)

If the automatic setup fails, follow these steps:

1. Import the SQL schema:

```bash
mysql -u root -p malwatch_db < backend/spam_schema.sql
```

2. Train the model:

```bash
python backend/train_spam_model.py
```

## Using the Spam Detection Feature

### For Users

1. Log in to your MalWatch Insight account
2. From the dashboard, click on the "Check Email" button
3. On the spam detection page:
   - Enter the email subject (optional)
   - Enter the sender's email address (optional)
   - Paste the email content (required)
   - Click "Check for Spam"
4. View the analysis results:
   - Classification (Spam or Not Spam)
   - Confidence percentage
   - Save the result for future reference

### For Administrators

Administrators can:

1. View all spam detection history from all users
2. Add new training data to the system
3. Retrain the model with new data:
   - Go to the admin panel
   - Navigate to the spam detection section
   - Click "Train Model"
   - View training results and model performance metrics

## How It Works

The spam detection system uses:

1. **Text preprocessing**: Cleaning and normalizing email text
2. **Feature extraction**: Converting text to TF-IDF features
3. **Naive Bayes classification**: Probabilistic model trained on labeled spam/ham emails
4. **Confidence scoring**: Probability-based confidence scores

## Troubleshooting

- **Model not loading**: Ensure the model files (spam_model.pkl and spam_vectorizer.pkl) exist in the backend directory
- **Database errors**: Check your MySQL connection settings in the .env file
- **Poor detection results**: Add more training data and retrain the model

## Contributing

To improve the spam detection:

1. Add more training examples to the `email_data` table
2. Improve the preprocessing functions in `spam_model.py`
3. Experiment with different ML algorithms by modifying the training script

## License

This feature is part of the MalWatch Insight application and is subject to the same license terms. 