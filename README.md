# Ask Your Data

Ask questions about your business data in plain English and get charts, key numbers and written insights in seconds.

Upload a CSV file, pick one or more datasets, and ask a question such as *"Which regions beat their target?"* or *"How has revenue changed over time?"*. The app uses Google Gemini to write the database query, runs it safely, and shows the answer as a chart, a highlighted number, a short summary, and the rows behind it.

## Features

- **Upload any CSV file.** Column names are cleaned up automatically, so `Order Date` becomes `order_date`.
- **Ask in plain English.** Gemini turns your question into a SQL query.
- **Review the query first.** Tick *Review the SQL before it runs* to see and edit the query before it runs.
- **Charts and insights.** Answers appear as bar, line or pie charts, with a short written summary.
- **Questions across datasets.** Select two or more datasets. The app joins them on a shared column, such as `region`.
- **Follow-up questions.** Ask *"now show it by month"* or *"only Europe"* and the previous query is adjusted.
- **Downloads.** Save the chart as a PNG image or the full result as a CSV file.
- **Private accounts.** Each person has a login and their own datasets, which other users cannot see.
- **Safe queries.** Only single `SELECT` queries can run. Anything that changes or deletes data is blocked.

## How it works

1. **Upload:** the CSV is saved into a database file for the logged-in user.
2. **Ask:** the app sends the question and the column names of the chosen datasets to Gemini, which returns a SQL query.
3. **Check:** the query is checked again on the server and must be a single `SELECT`.
4. **Run:** the query runs in read-only mode against the user's data.
5. **Show:** the result is drawn as a chart and table, with a written summary.

## Technology

- **Python** with **Flask** (web server)
- **pandas** (data handling) and **SQLite** (storage)
- **Google Gemini** (question understanding and insights)
- **Chart.js** (charts in the browser)
- **gunicorn** (production server)

## Running it on your computer

You need Python 3.10 or newer.

```bash
pip install -r requirements.txt

# Windows (Command Prompt)
set GEMINI_API_KEY=your-gemini-key
set SIGNUP_CODE=your-invite-code
python app.py
```

Then open http://127.0.0.1:5000, click **Create one**, and sign up with the invite code.

## Settings

The app reads these settings from the environment. Never put them in the code.

| Setting | Purpose |
|---|---|
| `GEMINI_API_KEY` | Your Google Gemini API key. Needed for questions and insights. |
| `SIGNUP_CODE` | Invite code people need to create an account. If it's empty, sign-up is closed. |
| `FLASK_SECRET_KEY` | Signs login sessions. Set a long random value on a server. |
| `DATA_DIR` | Folder where account and dataset files are kept. Point it at a persistent disk on a server. |
| `COOKIE_SECURE` | Set to `1` on a server that uses HTTPS. |
| `PORT` | Port to listen on. Hosting services usually set this for you. |

## Deploying

The project includes a `render.yaml` file for [Render](https://render.com). Connect this repository in Render using **New → Blueprint**, then enter `GEMINI_API_KEY` and `SIGNUP_CODE` in the dashboard.

Storage on Render needs a paid plan with a persistent disk. Without one, uploads and accounts are lost when the app restarts.

## Project layout

```
ask-your-data/
├── app.py              # server, login, uploads, questions, downloads
├── requirements.txt    # Python libraries
├── render.yaml         # deployment settings for Render
├── templates/          # web pages (ask, index, login, register, table)
└── static/
    └── style.css       # styling
```

## Notes

- Login attempts are limited to 5 failures per address in 15 minutes.
- Questions use the Gemini API, so usage counts against your API quota.
- This is a small project. Before using it with sensitive data for many users, add HTTPS, backups and a review of the security settings.
