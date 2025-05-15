# Pathshala Election System

<div align="center">
    <img src="static/img/logos/logo.png" alt="Pathshala Logo" width="150">
</div>


School captain election system designed for election in [Pathshala Nepal Foundation](https://pathshala.edu.np) . This application helps schools conduct fair and transparent elections for student leadership positions.

## Features

- **Secure Voting**: Each student gets a unique voting code
- **Admin Dashboard**: Monitor election progress in real-time
- **Mobile Friendly**: Students can vote from any device
- **Gender-balanced Elections**: Support for electing both male and female candidates
- **Vote Management**: Administrators can revoke votes or reset the election if needed
- **Results Analysis**: View detailed voting statistics with class-wise breakdowns
- **Concurrent Voting**: Supports large numbers of students voting simultaneously

## Tech Stack

- Python with Flask
- SQLite Database
- HTML/CSS with Tailwind CSS
- JavaScript with jQuery

## Setup Guide

### Prerequisites

- Python 3.7+
- pip (Python package manager)

### Installation

1. Clone the repository
```bash
git clone https://github.com/dhunganaPradeep/Pathshala-Election.git
cd Pathshala-Election
```

2. Create and activate a virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Initialize the database
```bash
python -c "from app import init_db; init_db()"
```

5. Run the application in production mode
```bash
python app.py
```

6. Access the application
- Main voting page: http://localhost:5000
- Admin panel: http://localhost:5000/admin
- Default admin credentials: 
  - Username: admin
  - Password: admin

## Production Deployment

For production deployment, we recommend:
- Using a WSGI server like Gunicorn or uWSGI
- Setting up a reverse proxy with Nginx or Apache
- Ensuring all security headers are properly configured
- Running on HTTPS only
- Setting strong, unique values for all secret keys

## Usage

### For Administrators

1. Upload student data via Excel sheet
2. Add teacher accounts manually
3. Add election candidates with photos and manifestos
4. Generate and distribute voting codes
5. Monitor voting progress
6. View and export results

### For Voters

1. Enter the provided voting code
2. Select one male and one female candidate
3. Submit your vote

## Testing

### Concurrent Voting Tests

The system includes comprehensive tests to verify that multiple students can vote simultaneously without conflicts:

1. **Basic Test**: Run all tests with default settings (10 concurrent voters)
   ```bash
   python run_tests.py
   ```

2. **Full-Scale Test**: Test with all students voting simultaneously
   ```bash
   python run_tests.py --test test_multiple_concurrent_voters --voters 180
   ```

3. **What the Tests Verify**:
   - Voting codes are correctly validated
   - Multiple students can vote concurrently without race conditions
   - Votes are correctly recorded in the database
   - Students cannot vote more than once
   - System performance under high load

## Screenshots

*Coming soon*

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Developed by [Pradip Dhungana](https://dhunganapradip.com.np)
