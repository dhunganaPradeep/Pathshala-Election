# Pathshala Election System

![Pathshala Logo](static/img/logos/logo.png)


School captain election system designed for election in [Pathshala Nepal Foundation](https://pathshala.edu.np/). This application helps schools conduct fair and transparent elections for student leadership positions.

## Features

- **Secure Voting**: Each student gets a unique voting code
- **Admin Dashboard**: Monitor election progress in real-time
- **Mobile Friendly**: Students can vote from any device
- **Gender-balanced Elections**: Support for electing both male and female candidates
- **Vote Management**: Administrators can revoke votes or reset the election if needed
- **Results Analysis**: View detailed voting statistics with class-wise breakdowns

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

5. Run the application
```bash
python app.py
```

6. Access the application
- Main voting page: http://localhost:5000
- Admin panel: http://localhost:5000/admin
- Default admin credentials: 
  - Username: admin
  - Password: admin

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

## Screenshots

*Coming soon*

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Developed by [Pradip Dhungana](https://dhunganapradip.com.np)

## Contact

For support or inquiries, please contact:
- Email: [dhungana.pradip188@gmail.com](mailto:dhungana.pradip188@gmail.com)
- GitHub: [@dhunganaPradeep](https://github.com/dhunganaPradeep)

## Deployment on PythonAnywhere

### Setup Instructions

1. Sign up/login to [PythonAnywhere](https://www.pythonanywhere.com/)

2. Go to the Dashboard and open a Bash console

3. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Election.git
   # Or upload your files via the Files tab
   ```

4. Create a virtual environment:
   ```bash
   mkvirtualenv --python=/usr/bin/python3.9 election-env
   ```

5. Install the dependencies:
   ```bash
   cd Election
   pip install -r requirements.txt
   ```

6. Initialize the database (if not already done):
   ```bash
   python
   >>> from app import init_db
   >>> init_db()
   >>> exit()
   ```

7. Configure the web app:
   - Go to the Web tab in PythonAnywhere
   - Create a new web app
   - Select "Manual Configuration"
   - Select Python 3.9
   - Set the path to your virtualenv (e.g., `/home/yourusername/.virtualenvs/election-env`)
   - Set the WSGI configuration file

8. Edit the WSGI configuration file:
   - Replace the existing content with the provided wsgi.py file
   - Make sure to update the path to your project directory: `/home/yourusername/Election`

9. Create required directories:
   ```bash
   mkdir -p uploads
   mkdir -p flask_session
   mkdir -p static/img/candidates
   mkdir -p static/img/logos
   ```

10. Configure static files:
    - In the Web tab, add a static files mapping:
    - URL: `/static/` to Directory: `/home/yourusername/Election/static/`

11. Reload the web app and access it at yourusername.pythonanywhere.com

## Important Notes

- Make sure to modify the WSGI file to use your actual PythonAnywhere username
- If you need to make database changes, you can access sqlite via:
  ```bash
  sqlite3 election.db
  ```
- Set the `SECRET_KEY` in app.py to a unique value for production
- PythonAnywhere free tier has file size limitations; ensure your uploads respect these limits 