import pandas as pd
import json
path = r"c:\Users\91994\Downloads\fund-trail-project-main (1)\fund-trail-project-main\IFSC_CODES.xlsx"
df = pd.read_excel(path, dtype=str, keep_default_na=False)
print(list(df.columns))
print(json.dumps(df.head(5).to_dict(orient='records'), ensure_ascii=False))
