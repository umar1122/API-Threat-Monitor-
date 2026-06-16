"""
API Based Intelligent Malware Identification using LSTM

This script performs multiple tasks, including:
- Uploading and extracting dataset files
- Parsing and extracting features from JSON reports
- Performing classification using an LSTM (Long Short-Term Memory) model
- Interfacing with VirusTotal API for malware analysis
- Displaying dataset and results in a GUI using Tkinter

Author: [Your Name]
"""

# Import necessary libraries
from tkinter import *
import virustotal_python
from pprint import pprint
import zipfile
from tkinter import filedialog
from VTService import VTService
import time
import pandas as pd
import os, glob
import json
from tkinter import ttk
from tkinter import messagebox
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np

# Import deep learning libraries
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

###########################################
# Function to create a new window for dataset visualization
###########################################
def new_win():
    """Creates a new window displaying the extracted dataset."""
    global top
    top = Toplevel()
    top.title("API Based Intelligent Malware Identification (Dataset)")
    top.minsize(705, 670)
    top.maxsize(705, 670)

    frame1 = ttk.LabelFrame(top, text="Dataset", width=378, height=370)
    frame1.place(x=7, y=95, width=680, height=540)

    Label(top, text="Extracted Dataset", width=35, font=("bold", 20)).place(x=107, y=50)

    global tv1
    tv1 = ttk.Treeview(frame1, height=14)
    tv1.place(relheight=1, relwidth=1)

    treescrolly = ttk.Scrollbar(frame1, orient="vertical", command=tv1.yview)
    treescrollx = ttk.Scrollbar(frame1, orient="horizontal", command=tv1.xview)
    tv1.configure(xscrollcommand=treescrollx.set, yscrollcommand=treescrolly.set)
    treescrollx.pack(side="bottom", fill="x")
    treescrolly.pack(side="right", fill="y")
    
    try:
        df = pd.read_csv('dataset_file.csv')
        global excelData
        excelData = df
        global allData
        allData = df.describe()
    except ValueError:
        messagebox.showerror("Information", "The file you have chosen is invalid")
        return None
    
    clear_data()
    tv1["column"] = list(df.columns)
    tv1["show"] = "headings"
    for column in tv1["columns"]:
        tv1.heading(column, text=column)
    
    df_rows = df.to_numpy().tolist()
    for row in df_rows:
        tv1.insert("", "end", values=row)
    return None

# Function to clear dataset display
def clear_data():
    """Clears the data from the dataset visualization window."""
    tv1.delete(*tv1.get_children())
    return None

###########################################
# Function for feature extraction from JSON files
###########################################
def data_parsing():
    """Extracts features from JSON files and stores them in a DataFrame."""
    Features = ['ID', 'SHA256', 'Severity Score', 'Category', 'Package', 'Size', 'Type', 'Label']
    Dataset = pd.DataFrame(columns=Features)
    
    folder_path = 'analyses report'
    i = 1

    for file in glob.glob(os.path.join(folder_path, '*.json')):
        try:
            with open(file, 'r') as f:
                data = json.load(f)
            label = 'non-malicious' if data['info']['score'] < 1 else 'malicious'
            
            Dataset.loc[i] = [
                data['info']["id"], data["target"]["file"]["sha256"], data["info"]["score"],
                data["info"]["category"], data["info"]["package"], data["target"]["file"]["size"],
                data["target"]["file"]["type"], label
            ]
        except Exception as e:
            print(f"Error processing file {file}: {e}")
            continue
        i += 1
    
    Dataset.fillna(0, inplace=True)
    Dataset.to_csv('dataset_file.csv', index=False)
    print(Dataset.head())
    return Dataset

###########################################
# Classification using LSTM Model
###########################################
def classification():
    """Performs classification using an LSTM model and evaluates performance metrics."""
    Dataset = data_parsing()
    
    le = LabelEncoder()
    Dataset['Label'] = le.fit_transform(Dataset['Label'])
    
    X = Dataset.drop(['Label'], axis=1)
    Y = Dataset['Label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.30, random_state=7)
    
    # Reshaping for LSTM input
    X_train = np.array(X_train).reshape((X_train.shape[0], X_train.shape[1], 1))
    X_test = np.array(X_test).reshape((X_test.shape[0], X_test.shape[1], 1))
    
    model = Sequential()
    model.add(LSTM(50, return_sequences=True, input_shape=(X_train.shape[1], 1)))
    model.add(Dropout(0.2))
    model.add(LSTM(50, return_sequences=False))
    model.add(Dropout(0.2))
    model.add(Dense(1, activation='sigmoid'))
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    checkpoint = tf.keras.callbacks.ModelCheckpoint("lstm_model.h5", save_best_only=True)
    model.fit(X_train, y_train, epochs=20, batch_size=32, validation_data=(X_test, y_test),
              callbacks=[checkpoint])
    
    predictions = (model.predict(X_test) > 0.5).astype("int32")
    print(classification_report(y_test, predictions))
    
    loss, accuracy = model.evaluate(X_test, y_test)
    print(f"Test Accuracy: {accuracy:.4f}")
    return accuracy