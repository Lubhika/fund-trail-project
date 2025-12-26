import pandas as pd

file_path = 'fund-trail-project-main/uploads/BankAction_CompleteTrail19_11_2025_18_21_52.xlsx'
try:
    df = pd.read_excel(file_path, sheet_name='Money Transfer to')
    print(df.columns.tolist())
except Exception as e:
    print(e)
