
# chi-squared probablities
probablities = [0.771388499, 0.178120617, 0.029453015, 0.011220196,	0.004207574, 0, 0.004207574, 0, 0.001402525, 0]

# avg number of flows observed per bin in the normal dataset (no attack influence)
avg = [5.04587156,	1.165137615,	0.19266055,	0.073394495,	0.027522936,	0	,0.027522936,	0	,0.009174312,	0]

import pandas as pd
critical_value = 16.919

expected_dist = [p * a for p, a in zip(probablities, avg)]

import numpy as np
from scipy.stats import chi2_contingency

input = #'input directory to the files containing instance-wise binned feature csv for train and test'
import os
files = os.listdir(input)

for file in files:
    if file.endswith('.csv'):
        df = pd.read_csv(input + file)

        interval_columns = df.columns[2:-2]  # Assuming the last column is 'Total flows'
        print(interval_columns)

        # Extract the 'Total flows' column
        total_flows = df['Total flows']

        # Initialize a list to store chi-squared statistics for each row
        chi_squared_stats = []


        # Calculate chi-squared statistic for each row
        for index, row in df.iterrows():
            print(row)
            observed_values = row[interval_columns]
            print(observed_values)
            expected_values = [x * total_flows[index] for x in probablities]
            # Calculate chi-squared statistic using numpy
            chi_squared_stat = np.sum((expected_values - observed_values) ** 2 / total_flows[index])

            chi_squared_stats.append(chi_squared_stat)

        # Add the chi-squared statistics as a new column to the DataFrame
        df['Chi-squared statistic'] = chi_squared_stats

        # Save the CSV file

        # df.to_csv()







    


