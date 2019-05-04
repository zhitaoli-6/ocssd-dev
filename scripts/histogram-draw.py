import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
from matplotlib.ticker import MaxNLocator
from collections import namedtuple
from matplotlib.font_manager import FontProperties
from matplotlib.backends.backend_pdf import PdfPages

# red (178, 23, 0) #b21700
# gray (65, 65, 65) #414141
# bluegreen (49, 121, 125) #31797d
# springgreen #a020f0

# blue (81, 157, 210) #519DD2
# green (113, 173, 81) #71AD51 
# red (255, 94, 92) #FF5E5C 

n_groups = 4

navi_success_rate_lab = (187,671,242,215)

navi_ssuccess_rate_academic = (237,1283,722,768)



font = FontProperties(fname=r"Helvetica.ttf", size=12)
fig, ax = plt.subplots(figsize=(4, 2.5))
pp = PdfPages('/home/sirius/Pictures/nas/macro-bench.pdf')

index = np.arange(n_groups)
bar_width = 0.16
interval = 0.04

opacity = 1
error_config = {'ecolor': '#000000', 'elinewidth': 1, 'capsize': 3}

rects1 = ax.bar(index, navi_success_rate_lab, bar_width,
                color="#FFFFFF",
                #edgecolor="#1D485D",
                edgecolor="#333333",
                lw=1,
                hatch='/' * 3,
                label='RAIS5')

rects2 = ax.bar(index + bar_width + interval, navi_ssuccess_rate_academic, bar_width,
                color="#FFFFFF",
                #edgecolor="#AC536D",
                edgecolor="#333333",
                lw=1,
                hatch='--' * 3,
                label='Log-ROC')




fmt='%d%%'
#yticks = mtick.FormatStrFormatter(fmt)
#ax.yaxis.set_major_formatter(yticks)
#ax.set_xlabel('Distance', fontproperties=font, verticalalignment='center')
ax.set_ylabel('Throughput(MB/s)', fontproperties=font, verticalalignment='center')
ax.set_xticks(index + bar_width + interval)
ax.set_xticklabels(('RocksDB', 'Fileserver', 'Randomrw','Randomwrite'))
leg = ax.legend(loc='best', prop={'size': 9})
leg.get_frame().set_edgecolor('#000000')
leg.get_frame().set_linewidth(0.5)
plt.ylim(0, 1500)
# Set ticks grids and labels
for label in (ax.get_xticklabels() + ax.get_yticklabels()):
    label.set_fontproperties(font)
    label.set_fontsize(10)

fig.tight_layout()
#plt.show()
plt.savefig("/home/sirius/Pictures/nas/macro-bench.png", format='png', dpi=300)
pp.savefig()
pp.close()
