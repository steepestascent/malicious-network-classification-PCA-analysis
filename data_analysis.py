# %%
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import numpy as np
import pandas as pd

# Load Data
df = pd.read_csv('./data/UNSW_NB15_training-set.csv', index_col=0, header=0)

#%%
# Define plot function
def plot_bar_graph(ticks, benign, malicious, name):
    plt.figure()
    n_groups = len(ticks)
    # create plot
    fig, ax = plt.subplots()
    index = np.arange(n_groups)
    bar_width = 0.35
    opacity = 0.8
    
    rects1 = plt.bar(index, benign, bar_width,
    alpha=opacity,
    color='navy',
    label='Benign')
    
    rects2 = plt.bar(index + bar_width, malicious, bar_width,
    alpha=opacity,
    color='lightgreen',
    label='Malicious')
    
    plt.xlabel(name)
    plt.ylabel('Counts')
    plt.title('Counts by Category')
    plt.xticks(index + bar_width, ticks)
    plt.legend()
    
    plt.xticks(rotation=70)
    plt.savefig("images/{}.png".format(name), bbox_inches = "tight")
    plt.show()
    plt.close()

#%%
# Analyzes categorical feature by count with respect to the label
one_hot_encode = ['proto',	'service',	'state']

for name in one_hot_encode:
    value_counts = df[name].value_counts()
    ticks = value_counts.index
    benign = []
    malicious = []
    for v in value_counts.index:
        value_occurrence = df[df[name] == v].groupby(['label'])
        value_occurrence = value_occurrence.size().reset_index().rename(columns={0:'count'})
        benign_value = value_occurrence[value_occurrence["label"] == 0].reset_index()
        malicious_value = value_occurrence[value_occurrence["label"] == 1].reset_index()
        if len(benign_value) > 0:
            benign.append(benign_value['count'][0])
        else:
            benign.append(0)
        if len(malicious_value) > 0:
            malicious.append(malicious_value['count'][0])
        else:
            malicious.append(0)

    table_df = pd.DataFrame(columns=[name, 'benign_count', 'malicious_count'])

    for i in range(len(ticks)):
        table_df.loc[i] = [ticks[i],benign[i], malicious[i]]
    table_df.to_csv('data/{}_category_counts.csv'.format(name))
    
    # proto field has too many categories to plot neatly.
    if(name == 'proto'):
        continue

    plot_bar_graph(ticks, benign, malicious, name)


#%%
# Plot label distribution
df = pd.read_csv('./data/UNSW_NB15_training-set.csv', index_col=0, header=0)
plt.figure()
group = df.groupby(['label']).size().reset_index().rename(columns={0:'count'})
benign_value = group[group['label'] == 0]['count'][0]
malicious_value = group[group['label'] == 1]['count'][1]


objects = ('Benign', 'Malicious')
y_pos = np.arange(len(objects))
performance = [benign_value, malicious_value] 
barlist = plt.bar(y_pos, performance, align='center', alpha=0.5)
barlist[0].set_color('navy')
barlist[1].set_color('lightgreen')
plt.xticks(y_pos, objects)
plt.ylabel('Counts')
plt.title('Label Distribution')
plt.savefig('images/label_distribution.png',  bbox_inches = "tight")
plt.show()
