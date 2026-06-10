import pickle

with open("phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

print(model.feature_names_in_)
print("Number of features:", len(model.feature_names_in_))