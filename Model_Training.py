import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
import joblib

data = pd.read_csv(r"C:\Users\HP\OneDrive\Desktop\Internship Practice\Project\Physing Websites Identifier\final_features_1.csv")
df = pd.DataFrame(data)

parameters = {
    'n_estimators':[150],
    'max_depth': [12],
    'min_samples_leaf': [1],
    'max_features': ['sqrt'],
    'bootstrap': [False],
    'criterion': ['entropy'],
    'min_samples_split': [5]
}

X = df.drop(['url','status'], axis=1)
y = df['status']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=100, random_state=42
)

# grid_search = GridSearchCV(
#     estimator= RandomForestClassifier(random_state=42, class_weight='balanced'),
#     param_grid=parameters,
#     scoring= 'recall',
#     cv= 5,
#     verbose= 2
# )

# grid_search.fit(X_train, y_train)

# best_model = grid_search.best_estimator_

# print('Best found parameters: ', grid_search.best_params_)

# y_pred = best_model.predict(X_test)

model = RandomForestClassifier(
    random_state=42,
    n_estimators=150,
    max_depth=12,
    min_samples_leaf=1,
    max_features='sqrt',
    bootstrap=False,
    criterion='entropy',
    min_samples_split=5
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)

print(f"Accuracy: {accuracy:.2f}")
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")

# joblib.dump(model, r'C:\Users\HP\OneDrive\Desktop\Internship Practice\Project\Physing Websites Identifier\Physing Detector ML Model.joblib')

print('Model Saved!')