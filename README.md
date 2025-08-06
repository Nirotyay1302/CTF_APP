# CTF Web Application

A Capture The Flag (CTF) web platform for cybersecurity competitions, practice, and learning. This app allows users to register, solve challenges, and track their progress on a scoreboard.

## Features
- User registration and authentication
- Challenge listing and submission
- Real-time scoreboard
- Admin panel for challenge management
- Export scores to Excel
- Secure handling of user data

## Getting Started

### Prerequisites
- Python 3.8+
- pip
- (Optional) MySQL for production database

### Installation
1. **Clone the repository:**
   ```sh
   git clone https://github.com/Nirotyay1302/CTF_APP.git
   cd CTF_APP
   ```
2. **Create a virtual environment:**
   ```sh
   python -m venv venv
   venv\Scripts\activate  # On Windows
   # or
   source venv/bin/activate  # On Linux/Mac
   ```
3. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
4. **Set up the database:**
   - For SQLite (default):
     ```sh
     python seed_challenges.py
     ```
   - For MySQL: See `MYSQL_SETUP_GUIDE.md`.

5. **Run the app:**
   ```sh
   python app.py
   ```
   The app will be available at `http://127.0.0.1:5000/`.

## Usage
- Register a new user or log in.
- Browse and solve challenges.
- View your ranking on the scoreboard.
- Admins can add/edit challenges and export results.

## Security Notes
- Sensitive files (database, venv, exports) are excluded from version control via `.gitignore`.
- Do not commit secrets or credentials to the repository.
- Use environment variables for production secrets.

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License
[Specify your license here]