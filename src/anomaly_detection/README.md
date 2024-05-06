## Chi-squared Analysis for Binned Features

This Python script performs chi-squared analysis for binned features based on the provided probabilities and average number of flows observed per bin in the normal dataset. It calculates the expected distribution, chi-squared statistic, and checks for significant deviations from the expected distribution.


### Usage

1. **Prepare Input Data**

   - Place the CSV files containing instance-wise binned feature data for train and test datasets in the specified input directory.

2. **Run the Script**

   - Execute the Python script `chi_squared_analysis.py`:
     ```bash
     python3 chi_squared_analysis.py
     ```

3. **Review Results**

   - The script will calculate the chi-squared statistic for each row in the CSV files and append the results as a new column.
   - Optionally, save the modified CSV files with the added chi-squared statistics column.

### Important Note

- Ensure the input CSV files have the expected structure with binned feature intervals as columns and 'Total flows' as the last column.

### Example

An example input CSV file might look like this:

```
| Instance | Feature1_bin1 | Feature1_bin2 | ... | Total flows |
|----------|---------------|---------------|-----|-------------|
|   1      |       10      |       20      | ... |     100     |
|   2      |       15      |       25      | ... |     150     |
|   ...    |      ...      |      ...      | ... |     ...     |
```
