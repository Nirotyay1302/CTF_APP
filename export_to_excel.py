from app import app, db
import pandas as pd
from datetime import datetime
from app import User, Challenge, Submission, AuditLog


def _build_scoreboard_dataframe():
    players = User.query.all()
    rows = []
    for user in players:
        submissions = Submission.query.filter_by(user_id=user.id, correct=True).all()
        total_score = sum(Challenge.query.get(sub.challenge_id).points for sub in submissions)
        solved_count = len(set(sub.challenge_id for sub in submissions))
        rows.append({
            "Username": user.username,
            "Score": total_score,
            "Challenges Solved": solved_count,
            "Last Submission": max([sub.timestamp for sub in submissions], default=None)
        })
    scoreboard_df = pd.DataFrame(rows).sort_values(by="Score", ascending=False)
    return scoreboard_df


def _build_summary_dataframe():
    total_players = User.query.count()
    total_challenges = Challenge.query.count()
    total_solves = Submission.query.filter_by(correct=True).count()
    max_possible_score = db.session.query(db.func.sum(Challenge.points)).scalar() or 0
    summary_df = pd.DataFrame([{ 
        "Total Players": total_players,
        "Total Challenges": total_challenges,
        "Total Solves": total_solves,
        "Max Possible Score": max_possible_score
    }])
    return summary_df


def export_all_to_excel():
    with app.app_context():
        scoreboard_df = _build_scoreboard_dataframe()
        summary_df = _build_summary_dataframe()

        # --- Export to Excel ---
        file_name = "CTF_GAME.xlsx"
        with pd.ExcelWriter(file_name, engine='openpyxl') as writer:
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            scoreboard_df.to_excel(writer, sheet_name='Scoreboard', index=False)

        print(f"✅ Exported successfully to {file_name}")

if __name__ == "__main__":
    export_all_to_excel()


def create_excel_report(filename: str = "CTF_GAME.xlsx") -> str:
    """Create an Excel report with Summary and Scoreboard sheets.
    Returns the created filename.
    """
    with app.app_context():
        scoreboard_df = _build_scoreboard_dataframe()
        summary_df = _build_summary_dataframe()
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            scoreboard_df.to_excel(writer, sheet_name='Scoreboard', index=False)
    return filename


def export_user_activity_report(filename: str = "CTF_User_Activity.xlsx") -> str:
    """Export a user activity report from AuditLog if available."""
    with app.app_context():
        # Load audit logs if table exists and has rows
        try:
            logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
        except Exception:
            logs = []
        activity_rows = [{
            "User": log.user,
            "Action": log.action,
            "Timestamp": log.timestamp
        } for log in logs]
        activity_df = pd.DataFrame(activity_rows)
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            if not activity_df.empty:
                activity_df.to_excel(writer, sheet_name='Activity', index=False)
            else:
                # Write an empty sheet with headers
                pd.DataFrame(columns=["User", "Action", "Timestamp"]).to_excel(writer, sheet_name='Activity', index=False)
    return filename
            