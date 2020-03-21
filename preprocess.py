# %%
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import MinMaxScaler
from sklearn.decomposition import PCA
import joblib
import os

# Load data
df = pd.read_csv('./data/UNSW_NB15_training-set.csv', index_col=0, header=0)

#%%
# Combine proto categories to other
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

df.loc[df['proto'].isin(proto_to_combine), 'proto'] = 'other'

# %%
# One Hot Encode Data
one_hot_encode = ['proto',	'service',	'state']
enc = OneHotEncoder()
enc.fit(df[one_hot_encode].values)
ohe = enc.transform(df[one_hot_encode])
df.drop(one_hot_encode, inplace=True, axis=1)
columns = np.concatenate([i for i in enc.categories_])
ohedf = pd.concat(
    [df, pd.DataFrame(ohe.toarray(), columns=columns, index=df.index)], axis=1)

# %%
# Scale
X = ohedf.drop(['label', 'attack_cat'], axis=1)
y = ohedf['label']
scaler = MinMaxScaler()
scaler.fit(X)
mmdf = pd.DataFrame(scaler.transform(X))
mmdf.columns = X.columns


#%%
# Dimensionality Reduction
pca = PCA()
X_pca = pca.fit_transform(mmdf)

#%%
# save data
mmdf['attack_cat'] = ohedf['attack_cat']
mmdf['label'] = y
mmdf.to_csv('data/minmax_scaled.csv')
pca_df = pd.DataFrame(X_pca)
pca_df['attack_cat'] = ohedf['attack_cat']
pca_df['label'] = y
pca_df.to_csv('data/pca.csv')

#%%
# Save artifacts
os.mkdir('artifacts')

joblib.dump(pca, 'artifacts/pca.pkl')
joblib.dump(scaler, 'artifacts/minmax_scaler.pkl')
joblib.dump(enc, 'artifacts/one_hot_encoder.pkl')


#%%
# Plot first 10 principle components
plt.figure()
objects = [i for i in range(1, 11)]
y_pos = np.arange(len(objects))
variance = np.array(pca.explained_variance_)[:10]
barlist = plt.bar(y_pos, variance, align='center', alpha=0.5)
plt.plot(y_pos, variance, linestyle='-', marker='o')
plt.xticks(y_pos, objects)
plt.ylabel('Variance')
plt.xlabel('Principle Components')
plt.title('Explained Variance')
plt.savefig('images/principle_components.png',  bbox_inches = "tight")
plt.show()

# %%
# Plot first 2 eigenvectors
plt.figure()
plt.grid()
colors = ['navy', 'lightgreen']
target_names = ['benign', 'malicious']
lw = 2
for color, i, target_name in zip(colors, [0, 1], target_names):
    plt.scatter(X_pca[y == i, 0], X_pca[y == i, 1], color=color, alpha=.8, lw=lw,
                label=target_name)
plt.legend(loc='best', shadow=False, scatterpoints=1)
plt.title('PCA Network Traffic')
plt.savefig('images/pca2d.png')
plt.show()

# %%
# Plot benign 2 eigenvectors
plt.figure()
plt.grid()
colors = ['navy']
target_names = ['benign']
lw = 2
for color, i, target_name in zip(colors, [0], target_names):
    plt.scatter(X_pca[y == i, 0], X_pca[y == i, 1], color=color, alpha=.8, lw=lw,
                label=target_name)
plt.legend(loc='best', shadow=False, scatterpoints=1)
plt.title('Benign PCA Network Traffic')
plt.savefig('images/pca2dBenign.png')
plt.show()

#%% 
# Plot malicious 2 eigenvectors
plt.figure()
plt.grid()
colors = ['lightgreen']
target_names = ['malicious']
lw = 2
for color, i, target_name in zip(colors, [1], target_names):
    plt.scatter(X_pca[y == i, 0], X_pca[y == i, 1], color=color, alpha=.8, lw=lw,
                label=target_name)
plt.legend(loc='best', shadow=False, scatterpoints=1)
plt.title('Malicious PCA Network Traffic')
plt.savefig('images/pca2dMalicious.png')
plt.show()

# %%
# plot first 3 eigenvector
plt.close()
fig = plt.figure(1, figsize=(8, 6))
ax = Axes3D(fig, elev=-150, azim=110)
ax.scatter(X_pca[:, 0], X_pca[:, 1], X_pca[:, 2], c=y,
    cmap='winter', edgecolor='k', s=40)
ax.set_title("First three PCA directions")
ax.set_xlabel("1st eigenvector")
ax.set_ylabel("2nd eigenvector")
ax.set_zlabel("3rd eigenvector")
plt.savefig('images/pca3d.png')
plt.show()


# %%
# plot first 3 Benign eigenvector
plt.close()
fig = plt.figure(1, figsize=(8, 6))
ax = Axes3D(fig, elev=-150, azim=110)
ax.scatter(X_pca[y==0][:, 0], X_pca[y==0][:, 1], X_pca[y==0][:, 2],
    color=['navy'], edgecolor='k', s=40)
ax.set_title("Benign First three PCA directions")
ax.set_xlabel("1st eigenvector")
ax.set_ylabel("2nd eigenvector")
ax.set_zlabel("3rd eigenvector")
plt.savefig('images/pca3dBenign.png')
plt.show()


# %%
# plot first 3 Malicious eigenvector
plt.close()
fig = plt.figure(1, figsize=(8, 6))
ax = Axes3D(fig, elev=-150, azim=110)
ax.scatter(X_pca[y==1][:, 0], X_pca[y==1][:, 1], X_pca[y==1][:, 2],
    color=['lightgreen'], edgecolor='k', s=40)
ax.set_title("Malicious First three PCA directions")
ax.set_xlabel("1st eigenvector")
ax.set_ylabel("2nd eigenvector")
ax.set_zlabel("3rd eigenvector")
plt.savefig('images/pca3dMalicious.png')
plt.show()
