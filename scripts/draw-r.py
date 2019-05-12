"""
Demo of the histogram (hist) function used to plot a cumulative distribution.

"""
import numpy as np
from matplotlib.font_manager import FontProperties
import matplotlib.pyplot as plt
from scipy.interpolate import spline
from matplotlib.backends.backend_pdf import PdfPages

# red (178, 23, 0) #b21700
# gray (65, 65, 65) #414141
# bluegreen (49, 121, 125) #31797d
# springgreen #a020f0

prefix = 'fio-seq'
#prefix = 'fio-ran'
suffix = 'r'

work_name = '%s-%s' % (prefix, suffix)


def get_data(path):
    input = open(path)
    data_x = []
    data_y = []
    while 1:
        line = input.readline()
        if not line:
            break
        else:
            data_x.append(float(line.split()[0]))
            data_y.append(float(line.split()[1]))
    input.close()
    return data_x,data_y

data_x_1, data_y_1 = get_data("rais5-%s.txt" % work_name)
data_x_2,data_y_2 = get_data("log-roc-%s.txt" % work_name)


font = FontProperties(fname=r"Helvetica.ttf", size=11)
#font = FontProperties(size=11)
plt.figure(figsize=(4, 2.5))
ax = plt.subplot()




# Print information
pp = PdfPages('/home/sirius/Pictures/nas/%s.pdf' % work_name)


plt.plot( data_x_1,data_y_1, marker = 'o',color='black', label='RAIS5')
plt.plot( data_x_2,data_y_2, marker = '^', color='black', label='Log-ROC')



# Set ticks grids and labels
for label in (ax.get_xticklabels() + ax.get_yticklabels()):
    label.set_fontproperties(font)
    label.set_fontsize(10)
plt.grid(linestyle='--', linewidth=0.5, zorder=1)
plt.ylim(-0.03, 1)
xx = np.array([1,3,5,7,9,11])
plt.xticks(xx,['4', '16', '64', '256', '1024','4096'])
plt.xlabel('Block Size(KB)', fontproperties=font, verticalalignment='center')
plt.ylabel('Read Amplification', fontproperties=font, verticalalignment='center')

#ax = plt.gca()
#ax.spines['top'].set_visible(False)
#ax.spines['right'].set_visible(False)

leg = plt.legend(loc='best', prop={'size': 9})
#leg = plt.legend()
leg.get_frame().set_edgecolor('#000000')
leg.get_frame().set_linewidth(0)

plt.tight_layout()
#plt.show()
plt.savefig("/home/sirius/Pictures/nas/%s.png" % work_name, dpi = 300)
pp.savefig()
pp.close()
