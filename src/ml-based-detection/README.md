**ML-based detection**

(1) Automatic identification of top features: Our approach involves developing an automated technique to extract traffic trace features using FRR state information (such as retransmission counts and packet delays per epoch). Utilizing machine learning, we then determine the top-k features that best enhance detection accuracy.

(2) Run-time attack detection: Building upon the identified top-k features, we propose a real-time attack detection approach. This method uses the trained ML model to detect attacks during runtime for each incoming FRR system state.

### To run the code, follow the instructions:

```
python3 automatic_feature_extraction.py
```

Note: Change the input pcap_file, log_file and ret_file with appropriate trace and state information respectively. This code is custoamized for Blink system.