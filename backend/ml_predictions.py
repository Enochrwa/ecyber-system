import pandas as pd
import numpy as np

from sniff import process_flows

df = pd.read_csv("web_attack_features.csv")

df_ready = process_flows(df)
