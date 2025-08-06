from app import app, db
import pandas as pd
from datetime import datetime
from app import User, Challenge, Submission


def export_all_to_excel():
    with app.app_context():
        # --- Player-wise Scoreboard ---
        players = User.query.all()
        data = []
        for user in players:
            submissions = Submission.query.filter_by(user_id=user.id, correct=True).all()
            total_score = sum(Challenge.query.get(sub.challenge_id).points for sub in submissions)
            solved_count = len(set(sub.challenge_id for sub in submissions))
            data.append({
                "Username": user.username,
                "Score": total_score,
                "Challenges Solved": solved_count,
                "Last Submission": max([sub.timestamp for sub in submissions], default=None)
            })

        scoreboard_df = pd.DataFrame(data).sort_values(by="Score", ascending=False)

        # --- Summary Statistics ---
        total_players = len(players)
        total_challenges = Challenge.query.count()
        total_solves = Submission.query.filter_by(correct=True).count()
        max_possible_score = db.session.query(db.func.sum(Challenge.points)).scalar() or 0

        summary_df = pd.DataFrame([{
            "Total Players": total_players,
            "Total Challenges": total_challenges,
            "Total Solves": total_solves,
            "Max Possible Score": max_possible_score
        }])

        # --- Export to Excel ---
        file_name = "CTF_Scoreboard.xlsx"
        with pd.ExcelWriter(file_name, engine='openpyxl') as writer:
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            scoreboard_df.to_excel(writer, sheet_name='Scoreboard', index=False)

        print(f"✅ Exported successfully to {file_name}")

if __name__ == "__main__":
    export_all_to_excel()
            