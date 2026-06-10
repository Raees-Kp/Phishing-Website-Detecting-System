from flask import Flask, render_template, request
import pickle
import pandas as pd
from feature_extractor import extract_features

app = Flask(__name__)

with open("phishing_model.pkl", "rb") as file:
    model = pickle.load(file)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():

    url = request.form["url"]

    features = extract_features(url)

    analysis = []

    print(features)

    # HTTPS Check
    if features["SSLfinal_State "] == 1:
        analysis.append("HTTPS Enabled")
    else:
        analysis.append("HTTPS Not Enabled")

    # IP Address Check
    if features["having_IPhaving_IP_Address "] == -1:
        analysis.append("No IP Address in URL")
    else:
        analysis.append("IP Address Detected in URL")

    # URL Shortener Check
    if features["Shortining_Service "] == -1:
        analysis.append("No URL Shortener Detected")
    else:
        analysis.append("URL Shortener Detected")

    # DNS Record Check
    if features["DNSRecord "] == 1:
        analysis.append("DNS Record Found")
    else:
        analysis.append("DNS Record Not Found")

    # Domain Age Check
    if features["age_of_domain "] == 1:
        analysis.append("Domain Age Verified")
    else:
        analysis.append("Domain Age Not Verified")

    df = pd.DataFrame([features])

    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0]

    if prediction == 1:
        result = "Legitimate Website ✅"
        confidence = round(probability[1] * 100, 2)
    else:
        result = "Phishing Website ⚠️"
        confidence = round(probability[0] * 100, 2)

    return render_template(
        "index.html",
        entered_url=url,
        result=result,
        confidence=confidence,
        analysis=analysis
    )


if __name__ == "__main__":
    app.run(debug=True)