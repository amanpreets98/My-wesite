import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import load_iris

# Load example data (replace with your phishing dataset)
data = load_iris()
X, y = data.data, data.target

# Train a simple model
model = RandomForestClassifier()
model.fit(X, y)

# Save the model to 'model.pkl'
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Model trained and saved to model.pkl")
