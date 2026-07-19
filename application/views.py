from django.shortcuts import render,redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import login ,logout,authenticate
from django.core.files.storage import default_storage
import matplotlib.pyplot as plt
import pandas as pd
import os
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import Input, Conv1D, MaxPooling1D, Dropout, Flatten, BatchNormalization
from xgboost import XGBClassifier
import joblib
import tensorflow as tf
from tensorflow.keras.layers import GRU
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import Input, Conv1D, MaxPooling1D, Dropout, Flatten, Dense, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.utils import to_categorical
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
import numpy as np
import os
import matplotlib.pyplot as plt
import seaborn as sns
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import Input, Conv1D, Add, BatchNormalization, Activation, MaxPooling1D, Flatten, Dense
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.utils import to_categorical

# Required for plotting
import matplotlib.pyplot as plt
import seaborn as sns

# Declare label list (used in your classification report & confusion matrix)
Label = ["legitimate", "phishing"]

# Create your views here.
def home(request):
    return render(request,'Home.html')

from django.shortcuts import render

def about(request):
    return render(request, 'about.html')

def register(request):
    if request.method == 'POST':
        First_Name = request.POST['name']
        Email = request.POST['email']
        username = request.POST['username']
        password = request.POST['password']
        confirmation_password = request.POST['cnfm_password']
        select_user=request.POST['role']
        if select_user=='admin':
            admin=True
        else:
            admin=False
        if password == confirmation_password:
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists, please choose a different one.')
                return redirect('register')
            else:
                if User.objects.filter(email=Email).exists():
                    messages.error(request, 'Email already exists, please choose a different one.')
                    return redirect('register')
                else:
                    user = User.objects.create_user(
                        username=username,
                        password=password,
                        email=Email,
                        first_name=First_Name,
                        is_staff=admin
                    )
                    user.save()
                    return redirect('login')
        else:
            messages.error(request, 'Passwords do not match.')
        return render(request, 'register.html')
    return render(request, 'register.html')
def login_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        if User.objects.filter(username=username).exists():
            user=User.objects.get(username=username)
            if user.check_password(password):
                user = authenticate(username=username,password=password)
                if user is not None:
                    login(request,user)
                    messages.success(request,'login successfull')
                    return redirect('/')
                else:
                   messages.error(request,'please check the Password Properly')
                   return redirect('login')
            else:
                messages.error(request,"please check the Password Properly")  
                return redirect('login') 
        else:
            messages.error(request,"username doesn't exist")
            return redirect('login')
    return render(request,'login.html')
def logout_view(request):
    logout(request)
    return redirect('login')

import os

# Ensure 'static/images' directory exists
os.makedirs(os.path.join('static', 'images'), exist_ok=True)
chart_path = os.path.join('static', 'images', 'performance_chart.png')


from django.shortcuts import render
from django.core.files.storage import default_storage
import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.models import load_model

# Global variables
X = y = df = None
le = LabelEncoder()
labels = ["legitimate", "phishing"]  # Based on earlier context

# ----------------- UPLOAD FUNCTION -----------------
def Upload_data(request):
    load = True
    global df, x, y

    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        file_path = default_storage.save(uploaded_file.name, uploaded_file)

        # Read uploaded file
        df = pd.read_csv(default_storage.path(file_path), low_memory=False)
        df = df.drop(['length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 
              'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 
              'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash', 
              'http_in_path', 'https_token', 'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port', 'tld_in_path', 
              'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains', 'prefix_suffix', 'random_domain', 'shortening_service', 
              'path_extension', 'nb_redirection', 'nb_external_redirection', 'length_words_raw', 'char_repeat', 'shortest_words_raw',
              'shortest_word_host', 'shortest_word_path', 'longest_words_raw', 'longest_word_host', 'longest_word_path', 'avg_words_raw', 
              'avg_word_host', 'avg_word_path', 'phish_hints', 'domain_in_brand', 'brand_in_subdomain', 'brand_in_path', 'suspecious_tld', 
              'statistical_report', 'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks', 'nb_extCSS', 
              'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors', 'ratio_extErrors', 'login_form', 'external_favicon', 
              'links_in_tags', 'submit_email', 'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe', 'popup_window', 'safe_anchor', 'onmouseover', 
              'right_clic', 'empty_title', 'domain_in_title', 'domain_with_copyright', 'whois_registered_domain', 'domain_registration_length',
              'domain_age', 'web_traffic', 'dns_record', 'google_index', 'page_rank'], axis = 1)

        # Drop unwanted columns
        

        # Delete file after reading
        default_storage.delete(file_path)

        # Preview uploaded data
        outdata = df.head(100)

        return render(request, 'prediction.html', {'predict': outdata.to_html(classes='table table-striped')})

    return render(request, 'prediction.html', {'upload': load})

# ----------------- PREP+ROCESS FUNCTION -----------------
# ----------------- PREPROCESS FUNCTION -----------------
from django.shortcuts import render
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

# Globals
df, x, y, le, X_train, X_test, y_train, y_test = None, None, None, None, None, None, None, None

def preprocess(request):
    global df, X, y, X_train, X_test, y_train, y_test

    # Load dataset
    if 'df' not in globals() or df is None:
        df = pd.read_csv("dataset_phishing.csv")

    # Reproducibility
    SEED = 42
    random.seed(SEED)
    np.random.seed(SEED)
    os.environ['PYTHONHASHSEED'] = str(SEED)
    tf.random.set_seed(SEED)

    # Ensure model folder exists
    os.makedirs("model", exist_ok=True)

    # Drop rows with missing url/status
    df = df.dropna(subset=['url', 'status']).reset_index(drop=True)
    # Drop duplicates
    df = df.drop_duplicates(subset=['url', 'status']).reset_index(drop=True)

    # Label encoding
    def map_status_to_binary(x):
        s = str(x).strip().lower()
        if s in ('1', 'phish', 'phishing', 'malicious', 'bad', 'true', 'phishy'):
            return 1
        if s in ('0', 'legitimate', 'benign', 'good', 'false'):
            return 0
        if 'phish' in s or 'fraud' in s or 'malicious' in s:
            return 1
        return 0

    df['label'] = df['status'].apply(map_status_to_binary)
    print("Label counts:\n", df['label'].value_counts())

    # Define features & labels
    X = df['url'].astype(str)   # raw url input
    y = df['label'].astype(int)

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=SEED, stratify=y
    )

    # TF-IDF vectorization
    TFIDF_PATH = "model/tfidf_char_ngram.joblib"
    if not os.path.exists(TFIDF_PATH):
        vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), max_features=5000)
        X_train_tfidf = vectorizer.fit_transform(X_train)
        X_test_tfidf = vectorizer.transform(X_test)
        joblib.dump(vectorizer, TFIDF_PATH)
        print("TF-IDF fitted and saved.")
    else:
        vectorizer = joblib.load(TFIDF_PATH)
        X_train_tfidf = vectorizer.transform(X_train)
        X_test_tfidf = vectorizer.transform(X_test)
        print("TF-IDF loaded from disk.")

    print("TF-IDF shapes:", X_train_tfidf.shape, X_test_tfidf.shape)

    # Preview first 10 rows
    preview_df = df[['url', 'status', 'label']].head(10)

    return render(request, "prediction.html", {
        "message": "✅ Preprocessing completed and phishing dataset encoded successfully.",
        "preview": preview_df.to_html(classes="table table-bordered table-sm")
    })



from django.shortcuts import render
import numpy as np
import pandas as pd
import random
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Global variables to access processed features
#X_selected = y_selected = None

precision = []
recall = []
fscore = []
accuracy = []
import threading
def performance_metrics(algorithm, predict, testY):
    # Calculate performance metrics
    testY = testY.astype('int64')
    predict = predict.astype('int64')
    p = precision_score(testY, predict, average='macro') * 100
    r = recall_score(testY, predict, average='macro') * 100
    f = f1_score(testY, predict, average='macro') * 100
    a = accuracy_score(testY, predict) * 100
    accuracy.append(a)
    precision.append(p)
    recall.append(r)
    fscore.append(f)

    # Print metrics
    print(f'{algorithm} Accuracy    : {a}')
    print(f'{algorithm} Precision   : {p}')
    print(f'{algorithm} Recall      : {r}')
    print(f'{algorithm} FSCORE      : {f}')

    # Classification report
    report = classification_report(testY, predict, target_names=Label)
    print(f'\n{algorithm} classification report\n{report}')

    # Confusion matrix
    conf_matrix = confusion_matrix(testY, predict)

    # Create the plot in the main thread to avoid potential issues
    def show_plot():
        plt.figure(figsize=(5, 5))
        ax = sns.heatmap(conf_matrix, xticklabels=Label, yticklabels=Label, annot=True, cmap="Spectral", fmt="g")
        ax.set_ylim([0, len(Label)])
        plt.title(f'{algorithm} Confusion matrix')
        plt.ylabel('True class')
        plt.xlabel('Predicted class')
        plt.show()
        plt.close()
    # Execute the plot display in the main thread
    if threading.current_thread().name == "MainThread":
        show_plot()
    else:
        # Use this if needed for threading environments
        threading.Thread(target=show_plot).start()
    
   
from django.shortcuts import render
import os
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# Make sure these are defined globally or load them inside the view
# X_train, X_test, y_train, y_test

def performance_metrics(name, y_pred, y_true, y_prob=None):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    roc = roc_auc_score(y_true, y_prob) if y_prob is not None else None

    print(f"\n{name} Metrics:")
    print(f"Accuracy: {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall: {rec:.4f}")
    print(f"F1-Score: {f1:.4f}")
    if roc is not None:
        print(f"ROC-AUC: {roc:.4f}")
    return acc, prec, rec, f1, roc


def train_logreg_view(request):
    SEED = 42
    os.makedirs('model', exist_ok=True)
    model_path = 'model/logreg_tfidf.joblib'
    tfidf_path = 'model/tfidf_char_ngram.joblib'

    # ---------------------------
    # Load or fit TF-IDF vectorizer
    # ---------------------------
    if not os.path.exists(tfidf_path):
        vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(3,5), max_features=5000)
        X_train_tfidf = vectorizer.fit_transform(X_train)
        X_test_tfidf = vectorizer.transform(X_test)
        joblib.dump(vectorizer, tfidf_path)
        print("TF-IDF fitted and saved.")
    else:
        vectorizer = joblib.load(tfidf_path)
        X_train_tfidf = vectorizer.transform(X_train)
        X_test_tfidf = vectorizer.transform(X_test)
        print("TF-IDF loaded from disk.")
    print("TF-IDF shapes:", X_train_tfidf.shape, X_test_tfidf.shape)

    # ---------------------------
    # Load or train Logistic Regression
    # ---------------------------
    if os.path.exists(model_path):
        logreg = joblib.load(model_path)
        print("✅ Logistic Regression model loaded successfully.")
    else:
        print("❌ Model not found. Training Logistic Regression...")
        logreg = LogisticRegression(max_iter=1000, random_state=SEED)
        logreg.fit(X_train_tfidf, y_train)
        joblib.dump(logreg, model_path)
        print("✅ Logistic Regression model trained and saved.")

    # ---------------------------
    # Predictions
    # ---------------------------
    y_pred = logreg.predict(X_test_tfidf)
    y_prob = logreg.predict_proba(X_test_tfidf)[:, 1] if hasattr(logreg, "predict_proba") else None

    # ---------------------------
    # Evaluate
    # ---------------------------
    acc, prec, rec, f1, _ = performance_metrics("Logistic Regression", y_pred, y_test, y_prob)

    # ---------------------------
    # Return to template
    # ---------------------------
    return render(request, 'prediction.html', {
        'algorithm': 'Logistic Regression',
        'accuracy': f"{acc*100:.2f}%",
        'precision': f"{prec*100:.2f}%",
        'recall': f"{rec*100:.2f}%",
        'fscore': f"{f1*100:.2f}%"
    })



# --------------------------- Imports ---------------------------
import os
import joblib
import numpy as np
from django.shortcuts import render
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# If you have a shared evaluation function
def performance_metrics(name, y_true, y_pred, y_prob=None):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    # You can store metrics globally if needed
    global accuracy, precision, recall, fscore
    if 'accuracy' not in globals():
        accuracy, precision, recall, fscore = [], [], [], []
    accuracy.append(acc*100)
    precision.append(prec*100)
    recall.append(rec*100)
    fscore.append(f1*100)
    
    print(f"{name} - Accuracy: {acc:.2f}, Precision: {prec:.2f}, Recall: {rec:.2f}, F1: {f1:.2f}")
    return acc, prec, rec, f1, y_prob

# --------------------------- Random Forest View ---------------------------
def train_random_forest_view(request):
    from sklearn.tree import DecisionTreeClassifier

    SEED = 42
    os.makedirs('model', exist_ok=True)

    global X_train, X_test, y_train, y_test  # Make sure these are defined elsewhere

    tfidf_path = 'model/tfidf_char_ngram.joblib'
    model_path = 'model/rf_tfidf.joblib'

    # ---------------------------
    # Load or fit TF-IDF vectorizer
    # ---------------------------
    if X_train is None or X_test is None:
        return render(request, 'prediction.html', {'error': '❌ Dataset not loaded.'})

    if not os.path.exists(tfidf_path):
        vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(3,5), max_features=5000)
        X_train_tfidf = vectorizer.fit_transform(X_train)
        X_test_tfidf = vectorizer.transform(X_test)
        joblib.dump(vectorizer, tfidf_path)
        print("TF-IDF fitted and saved.")
    else:
        vectorizer = joblib.load(tfidf_path)
        X_train_tfidf = vectorizer.transform(X_train)
        X_test_tfidf = vectorizer.transform(X_test)
        print("TF-IDF loaded from disk.")
    print("TF-IDF shapes:", X_train_tfidf.shape, X_test_tfidf.shape)

    # ---------------------------
    # Load or train Random Forest
    # ---------------------------
    if os.path.exists(model_path):
        rf = joblib.load(model_path)
        print("✅ Random Forest model loaded successfully.")
    else:
        print("❌ Model not found. Training Random Forest...")
        rf = RandomForestClassifier(n_estimators=100, random_state=SEED)
        rf.fit(X_train_tfidf, y_train)
        joblib.dump(rf, model_path)
        print("✅ Random Forest model trained and saved.")

    # ---------------------------
    # Predictions
    # ---------------------------
    y_pred = rf.predict(X_test_tfidf)
    y_prob = rf.predict_proba(X_test_tfidf)[:, 1] if hasattr(rf, "predict_proba") else None

    # ---------------------------
    # Evaluate
    # ---------------------------
    acc, prec, rec, f1, _ = performance_metrics("Random Forest", y_pred, y_test, y_prob)

    # ---------------------------
    # Return results to template
    # ---------------------------
    return render(request, 'prediction.html', {
        'algorithm': 'Random Forest',
        'accuracy': f"{acc*100:.2f}%",
        'precision': f"{prec*100:.2f}%",
        'recall': f"{rec*100:.2f}%",
        'fscore': f"{f1*100:.2f}%"
    })



def train_decision_tree_view(request):
    from sklearn.tree import DecisionTreeClassifier

    SEED = 42
    os.makedirs('model', exist_ok=True)

    tfidf_path = 'model/tfidf_char_ngram.joblib'
    model_path = 'model/dt_tfidf.joblib'

    # ---------------------------
    # Load or fit TF-IDF vectorizer
    # ---------------------------
    if not os.path.exists(tfidf_path):
        vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(3,5), max_features=5000)
        X_train_tfidf = vectorizer.fit_transform(X_train)
        X_test_tfidf = vectorizer.transform(X_test)
        joblib.dump(vectorizer, tfidf_path)
        print("TF-IDF fitted and saved.")
    else:
        vectorizer = joblib.load(tfidf_path)
        X_train_tfidf = vectorizer.transform(X_train)
        X_test_tfidf = vectorizer.transform(X_test)
        print("TF-IDF loaded from disk.")
    print("TF-IDF shapes:", X_train_tfidf.shape, X_test_tfidf.shape)

    # ---------------------------
    # Load or train Decision Tree
    # ---------------------------
    if os.path.exists(model_path):
        dt = joblib.load(model_path)
        print("✅ Decision Tree model loaded successfully.")
    else:
        print("❌ Model not found. Training Decision Tree...")
        dt = DecisionTreeClassifier(random_state=SEED)
        dt.fit(X_train_tfidf, y_train)
        joblib.dump(dt, model_path)
        print("✅ Decision Tree model trained and saved.")

    # ---------------------------
    # Predictions
    # ---------------------------
    y_pred = dt.predict(X_test_tfidf)
    y_prob = dt.predict_proba(X_test_tfidf)[:, 1] if hasattr(dt, "predict_proba") else None

    # ---------------------------
    # Evaluate
    # ---------------------------
    acc, prec, rec, f1, _ = performance_metrics("Decision Tree", y_pred, y_test, y_prob)

    # ---------------------------
    # Return results to template
    # ---------------------------
    return render(request, 'prediction.html', {
        'algorithm': 'Decision Tree',
        'accuracy': f"{acc*100:.2f}%",
        'precision': f"{prec*100:.2f}%",
        'recall': f"{rec*100:.2f}%",
        'fscore': f"{f1*100:.2f}%"
    })



def train_proposed_mlp_view(request):
    import os
    import numpy as np
    from tensorflow.keras.models import Sequential, load_model
    from tensorflow.keras.layers import Dense, Dropout
    from sklearn.utils.class_weight import compute_class_weight

    SEED = 42
    os.makedirs('model', exist_ok=True)

    tfidf_path = 'model/tfidf_char_ngram.joblib'
    model_path = 'model/ProposedMLP_TFIDF.h5'

    # ---------------------------
    # Check dataset availability
    # ---------------------------
    if X_train is None or y_train is None or X_test is None or y_test is None:
        return render(request, 'prediction.html', {'error': '❌ Dataset not found or not processed yet.'})

    # ---------------------------
    # Load or fit TF-IDF vectorizer
    # ---------------------------
    if not os.path.exists(tfidf_path):
        vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(3,5), max_features=5000)
        X_train_tfidf = vectorizer.fit_transform(X_train)
        X_test_tfidf = vectorizer.transform(X_test)
        joblib.dump(vectorizer, tfidf_path)
        print("TF-IDF fitted and saved.")
    else:
        vectorizer = joblib.load(tfidf_path)
        X_train_tfidf = vectorizer.transform(X_train)
        X_test_tfidf = vectorizer.transform(X_test)
        print("TF-IDF loaded from disk.")
    print("TF-IDF shapes:", X_train_tfidf.shape, X_test_tfidf.shape)

    # ---------------------------
    # Convert sparse matrices to dense
    # ---------------------------
    x_train_dense = X_train_tfidf.toarray()
    x_test_dense = X_test_tfidf.toarray()

    # ---------------------------
    # Load or train Proposed MLP
    # ---------------------------
    try:
        if os.path.exists(model_path):
            model = load_model(model_path)
            print("✅ Proposed MLP model loaded successfully.")
        else:
            raise FileNotFoundError("Model file not found.")
    except Exception as e:
        print(f"❌ Loading failed due to: {e}. Retraining the Proposed MLP...")

        # Define MLP architecture
        model = Sequential([
            Dense(512, activation='relu', input_shape=(x_train_dense.shape[1],)),
            Dropout(0.3),
            Dense(256, activation='relu'),
            Dropout(0.3),
            Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

        # Handle class imbalance
        class_weights = compute_class_weight(class_weight='balanced', classes=np.unique(y_train), y=y_train)
        class_weight_dict = {i: w for i, w in enumerate(class_weights)}

        # Train the model
        model.fit(
            x_train_dense, y_train,
            validation_data=(x_test_dense, y_test),
            epochs=7,
            batch_size=64,
            class_weight=class_weight_dict,
            verbose=1
        )

        # Save model
        model.save(model_path)
        print("✅ Proposed MLP trained and saved.")

    # ---------------------------
    # Predictions
    # ---------------------------
    y_pred_prob = model.predict(x_test_dense).reshape(-1)
    y_pred = (y_pred_prob > 0.5).astype(int)

    # ---------------------------
    # Evaluate
    # ---------------------------
    acc, prec, rec, f1, _ = performance_metrics("Proposed MLP (TF-IDF)", y_pred, y_test, y_pred_prob)

    # ---------------------------
    # Return results to template
    # ---------------------------
    return render(request, 'prediction.html', {
        'algorithm': 'Proposed MLP (TF-IDF)',
        'accuracy': f"{acc*100:.2f}%",
        'precision': f"{prec*100:.2f}%",
        'recall': f"{rec*100:.2f}%",
        'fscore': f"{f1*100:.2f}%"
    })


  


import os
import pandas as pd
import matplotlib.pyplot as plt
from django.shortcuts import render

# Global metrics (you should ensure these are defined somewhere before this view is called)
accuracy = []
precision = []
recall = []
fscore = []

def performance_summary_view(request):
    global accuracy, precision, recall, fscore

    algorithm_names = ["Logistic model", "Decision Tree", "random forest model","Proposed MLP (TF-IDF)"]

    if len(accuracy) < len(algorithm_names):
        return render(request, 'prediction.html', {'error': '❌ Not all models have been evaluated yet.'})
       

    columns = ["Algorithm Name", "Precision", "Recall", "F1 Score", "Accuracy"]
    values = []

    for i in range(len(algorithm_names)):
        values.append([
            algorithm_names[i],
            round(precision[i], 2),
            round(recall[i], 2),
            round(fscore[i], 2),
            round(accuracy[i], 2)
        ])

    temp = pd.DataFrame(values, columns=columns)

    # Save performance chart to static/images/
    static_images_dir = os.path.join('static', 'images')
    os.makedirs(static_images_dir, exist_ok=True)  # Ensure directory exists

    chart_path = os.path.join(static_images_dir, 'performance_chart.png')

    # Plot the chart
    fig, axs = plt.subplots(2, 2, figsize=(10, 10))
    fig.suptitle("Performance Metrics of Different Models", fontsize=16)

    axs[0, 0].bar(temp["Algorithm Name"], temp["Precision"], color='skyblue')
    axs[0, 0].set_title("Precision")
    axs[0, 0].tick_params(axis='x', rotation=15)

    axs[0, 1].bar(temp["Algorithm Name"], temp["Recall"], color='orange')
    axs[0, 1].set_title("Recall")
    axs[0, 1].tick_params(axis='x', rotation=15)

    axs[1, 0].bar(temp["Algorithm Name"], temp["F1 Score"], color='green')
    axs[1, 0].set_title("F1 Score")
    axs[1, 0].tick_params(axis='x', rotation=15)

    axs[1, 1].bar(temp["Algorithm Name"], temp["Accuracy"], color='purple')
    axs[1, 1].set_title("Accuracy")
    axs[1, 1].tick_params(axis='x', rotation=15)

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(chart_path)
    plt.close()

    return render(request, 'prediction.html', {
        'table': temp.to_html(classes='table table-bordered table-hover', index=False),
        'chart_url': '/static/images/performance_chart.png'
    })

def predict_view(request):
    if request.method == 'POST' and request.FILES.get('file'):
        import pandas as pd
        import joblib
        from tensorflow.keras.models import load_model
        from django.core.files.storage import default_storage

        # Labels for predictions
        labels = {0: "legitimate", 1: "phishing"}

        # Read uploaded CSV file
        uploaded_file = request.FILES['file']
        file_path = default_storage.save(uploaded_file.name, uploaded_file)
        test = pd.read_csv(default_storage.path(file_path))
        default_storage.delete(file_path)

        # Ensure 'url' column exists
        if 'url' not in test.columns:
            return render(request, 'prediction.html', {
                'error': "Uploaded CSV must contain a 'url' column."
            })

        X_test_raw = test['url'].astype(str)

        # Load TF-IDF vectorizer and transform
        TFIDF_PATH = "model/tfidf_char_ngram.joblib"
        vectorizer = joblib.load(TFIDF_PATH)
        X_test_tfidf = vectorizer.transform(X_test_raw)

        # Load Proposed MLP model
        mlp = load_model("model/ProposedMLP_TFIDF.h5")
        X_test_dense = X_test_tfidf.toarray()  # Convert sparse TF-IDF to dense

        # Make Predictions
        y_pred_prob = mlp.predict(X_test_dense).reshape(-1)
        y_pred = (y_pred_prob > 0.5).astype(int)

        # Map numeric labels to readable strings
        test['Predicted_Label'] = [labels[int(p)] for p in y_pred]

        return render(request, 'prediction.html', {
            'predict': test[['url', 'Predicted_Label']].head(100).to_html(
                classes='table table-bordered', index=False
            )
        })

    return render(request, 'prediction.html', {'test': True})



