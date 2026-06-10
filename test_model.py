import pickle

with open("phishing_model.pkl", "rb") as file:
    model = pickle.load(file)

print(hasattr(model, "predict_proba"))