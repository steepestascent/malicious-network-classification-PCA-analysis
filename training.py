#%%
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.constraints import MaxNorm
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.utils import class_weight
import joblib
from datetime import datetime

#%%
# Prepare testing set
testing_set = pd.read_csv('data/UNSW_NB15_testing-set.csv', index_col=0, header=0)

proto_to_combine = ['sctp', 'any', 'gre', 'sun-nd', 'ipv6', 'swipe', 'pim', 'mobile',
'rsvp', 'sep', 'ib', 'ipx-n-ip', 'cphb', 'idpr', 'smp', 'ippc',
'eigrp', 'srp', 'kryptolan', '3pc', 'mtp', 'pri-enc', 'qnx',
'vmtp', 'xtp', 'skip', 'sm', 'ipv6-opts', 'dgp', 'mfe-nsp',
'etherip', 'vrrp', 'mhrp', 'fire', 'tlsp', 'idpr-cmtp', 'uti',
'pgm', 'i-nlsp', 'idrp', 'ddp', 'ipv6-no', 'narp', 'wb-mon',
'sat-mon', 'nsfnet-igp', 'ipv6-frag', 'merit-inp', 'aris',
'ipv6-route', 'scps', 'pipe', 'pvp', 'secure-vmtp', 'sat-expak',
'il', 'gmtp', 'ax.25', 'pnni', 'ttp', 'snp', 'bna', 'visa', 'sps',
'ddx', 'sccopmce', 'ipcv', 'br-sat-mon', 'isis', 'aes-sp3-d',
'encap', 'larp', 'tp++', 'iso-ip', 'iplt', 'wb-expak', 'fc',
'vines', 'cpnx', 'tcf', 'iatp', 'micp', 'sprite-rpc', 'cftp',
'a/n', 'stp', 'ifmp', 'compaq-peer', 'ipip', 'crudp', 'ipcomp',
'rvd', 'l2tp', 'wsn', 'zero', 'ptp', 'sdrp', 'cbt', 'ggp',
'leaf-2', 'pup', 'emcon', 'dcn', 'trunk-2', 'leaf-1', 'iso-tp4',
'mux', 'ip', 'st2', 'nvp', 'crtp', 'xns-idp', 'irtp', 'trunk-1',
'ipnip', 'chaos', 'prm', 'igp', 'xnet', 'netblt', 'rdp', 'bbn-rcc',
'argus', 'hmp', 'egp']

testing_set.loc[testing_set['proto'].isin(proto_to_combine), 'proto'] = 'other'

test_X = testing_set.drop(['label', 'attack_cat'], axis=1)
test_y = testing_set['label']

# Load artifacts
minmax_scaler = joblib.load('artifacts/minmax_scaler.pkl')
enc = joblib.load('artifacts/one_hot_encoder.pkl')
pca = joblib.load('artifacts/pca.pkl') 

# One hot encode
one_hot_encode = ['proto',	'service',	'state']
enc.handle_unknown = 'ignore'
ohe = enc.transform(test_X[one_hot_encode])
test_X.drop(one_hot_encode, inplace=True, axis=1)
columns = np.concatenate([i for i in enc.categories_])
test_X = pd.concat([test_X, pd.DataFrame(ohe.toarray(), columns=columns, index=test_X.index)], axis=1)


test_scaled_X = minmax_scaler.transform(test_X)
test_pca_X = pca.transform(test_scaled_X)


#%%
# Non PCA 
X_scaled_df = pd.read_csv('data/minmax_scaled.csv', index_col=0, header=0).sample(frac=1)
y_scaled_df = X_scaled_df['label'].to_numpy(dtype='uint8')
X_scaled_df = X_scaled_df.drop(['label', 'attack_cat'], axis=1).to_numpy()

model = keras.models.Sequential([
    keras.layers.Dense(70, input_shape=(70,), activation="relu", kernel_constraint=MaxNorm(3)),
    keras.layers.Dropout(rate=0.2),
    keras.layers.Dense(35, activation="relu", kernel_constraint=MaxNorm(3)),
    keras.layers.Dropout(rate=0.2),
    keras.layers.Dense(1, activation="sigmoid", kernel_constraint=MaxNorm(3))
])

opt = keras.optimizers.SGD(lr=0.001)
model.compile(loss="binary_crossentropy",
              optimizer=opt,
              metrics=["accuracy"])

class_weights = class_weight.compute_class_weight('balanced', np.unique( y_scaled_df), y_scaled_df)
history_scaled = model.fit(X_scaled_df, y_scaled_df, batch_size=32, epochs=10, class_weight=class_weights, validation_data=(test_scaled_X, test_y))


pd.DataFrame(history_scaled.history).plot(figsize=(8, 5))
plt.grid(True)
plt.gca().set_ylim(0, 1)
plt.savefig('images/scaled_histroy-{}.png'.format(datetime.now().strftime('%Y%m%d_%H-%M-%S')), bbox_inches = "tight")

#%%
# PCA 
X_pca_df = pd.read_csv('data/pca.csv', index_col=0, header=0).sample(frac=1)
y_pca_df = X_pca_df['label'].to_numpy(dtype='uint8')

for features in [5, 10, 20, 70]:
    print("PCA training with {} features.".format(features))
    X_pca_features_df = X_pca_df.drop(['label', 'attack_cat'], axis=1).iloc[:,:features].to_numpy()
    test_pca_features_X = test_pca_X[:,:features]
    
    
    model = keras.models.Sequential([
        keras.layers.Dense(features, input_shape=(features,), activation="relu", kernel_constraint=MaxNorm(3)),
        keras.layers.Dropout(rate=0.2),
        keras.layers.Dense(round(features/2), activation="relu", kernel_constraint=MaxNorm(3)),
        keras.layers.Dropout(rate=0.2),
        keras.layers.Dense(1, activation="sigmoid", kernel_constraint=MaxNorm(3))
    ])
    
    
    opt = keras.optimizers.SGD(lr=0.001)
    model.compile(loss="binary_crossentropy",
                  optimizer=opt,
                  metrics=["accuracy"])
    
    class_weights = class_weight.compute_class_weight('balanced', np.unique(y_pca_df), y_pca_df)
    
    history = model.fit(X_pca_features_df, y_pca_df, batch_size=32, epochs=10, class_weight=class_weights, validation_data=(test_pca_features_X, test_y))
    
    pd.DataFrame(history.history).plot(figsize=(8, 5))
    plt.grid(True)
    plt.gca().set_ylim(0, 1)
    plt.savefig('images/pca_{}_features_10_epochs-{}.png'.format(features, datetime.now().strftime('%Y%m%d_%H-%M-%S')), bbox_inches = "tight")

    print(model.summary())
    