# coding: latin-1
# FEA Configuration Settings Panel
#
# João Mota (2017)
#
# Class for storing and retrieving configuration settings for the Forensic Email Analysis Report Module
# joao.lx@gmail.com
#
# Links with example code in Java used as reference:
# http://www.sleuthkit.org/autopsy/docs/api-docs/4.3/_s_t_i_x_report_module_8java_source.html#l00069
# http://www.sleuthkit.org/autopsy/docs/api-docs/4.3/_s_t_i_x_report_module_config_panel_8java_source.html

from org.sleuthkit.autopsy.coreutils import ModuleSettings
from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import JSlider
from javax.swing import ButtonGroup
from javax.swing import JComboBox
from javax.swing import JList
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JLabel
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter

class FEA_ConfigPanel(JPanel):

    # cbNSLookup = JCheckBox()
    # cbGenerateCSV = JCheckBox()
    # cbGenerateExcel = JCheckBox()
    # numberThreadsSlider = JSlider()
    numThreads = 8
    generateXLS = True
    generateCSV = True
    doNSLookup = True
    doWBLookup = True
    cbNSLookup = None
    cbGenerateExcel = None
    cbGenerateCSV = None
    cbWayback = None

    def __init__(self):

        self.initComponents()
        
        # get previous settings selected by the user
        if (ModuleSettings.getConfigSetting("FEA", "doNSLookup") != None) and (ModuleSettings.getConfigSetting("FEA","doNSLookup") != ""):
            if ModuleSettings.getConfigSetting("FEA","doNSLookup"):
                self.cbNSLookup.setSelected(True)
                self.doNSLookup = True
            else:
                self.cbNSLookup.setSelected(False)
                self.doNSLookup = False

        if (ModuleSettings.getConfigSetting("FEA", "generateCSV") != None) and (ModuleSettings.getConfigSetting("FEA","generateCSV") != ""):
            if ModuleSettings.getConfigSetting("FEA","generateCSV"):
                self.cbGenerateCSV.setSelected(True)
                self.generateCSV = True
            else:
                self.cbGenerateCSV.setSelected(False)
                self.generateCSV = False
        if (ModuleSettings.getConfigSetting("FEA", "generateXLS") != None) and (ModuleSettings.getConfigSetting("FEA","generateXLS") != ""):
            if ModuleSettings.getConfigSetting("FEA","generateXLS"):
                self.cbGenerateExcel.setSelected(True)
                self.generateXLS = True
            else:
                self.cbGenerateExcel.setSelected(False)
                self.generateXLS = False
        if (ModuleSettings.getConfigSetting("FEA", "numThreads") != None) and (ModuleSettings.getConfigSetting("FEA","numThreads") != ""):
            self.numThreads = ModuleSettings.getConfigSetting("FEA", "numThreads")
            self.numberThreadsSlider.setValue(self.numThreads)
            #self.addStatusLabel("Read number of threads from previous config: " + self.numThreads)
        else:
            self.numThreads = self.numberThreadsSlider.getValue()

    def addStatusLabel(self, msg):
            gbc = GridBagConstraints()
            gbc.anchor = GridBagConstraints.NORTHWEST
            gbc.gridx = 0
            gbc.gridy = 7
            lab = JLabel(msg)
            self.add(lab, gbc)

    def getDoNSLookup(self):
        return self.doNSLookup

    def getGenerateCSV(self):
        return self.generateCSV

    def getGenerateXLS(self):
        return self.generateXLS

    def getDoWBLookup(self):
        return self.doWBLookup

    def getNumThreads(self):
        return self.numThreads

    def initComponents(self):
        self.setLayout(GridBagLayout())

        gbc = GridBagConstraints()
        gbc.anchor = GridBagConstraints.NORTHWEST
        gbc.gridx = 0
        gbc.gridy = 0

        descriptionLabel = JLabel("FEA - Forensics Email Analysis")
        self.add(descriptionLabel, gbc)

        gbc.gridy = 1
        self.cbNSLookup = JCheckBox("Perform DNS Lookup on email domains", actionPerformed=self.cbNSLookupActionPerformed)
        self.cbNSLookup.setSelected(True)
        self.add(self.cbNSLookup, gbc)


        # TODO: include option to browse for list with emails to exclude from analysis

        # blacklistLabel = JLabel("Email addresses to be excluded (blacklist):")
        # gbc.gridy = 1
        # panel0.add(blacklistLabel, gbc)

        # blacklistTextArea = JTextArea()
        # gbc.fill = GridBagConstraints.HORIZONTAL
        # gbc.gridy = 2
        # gbc.ipady = 40
        # panel0.add(blacklistTextArea, gbc)

        numberThreadsLabel = JLabel("Maximum number of threads for DNS Lookup task: ")
        gbc.gridy = 2
        self.add(numberThreadsLabel, gbc)

        self.numberThreadsSlider = JSlider(JSlider.HORIZONTAL, 1, 16, 8, stateChanged=self.sliderActionPerformed);
        self.numberThreadsSlider.setMajorTickSpacing(1)
        self.numberThreadsSlider.setPaintLabels(True)
        self.numberThreadsSlider.setPaintTicks(True)
        self.numberThreadsSlider.setSnapToTicks(True)
        self.numberThreadsSlider.setToolTipText("set maximum number of concurrent threads when performing DNS lookup on email domains")

        gbc.gridy = 5
        gbc.gridwidth = 15
        gbc.gridheight = 1
        gbc.fill = GridBagConstraints.BOTH
        gbc.weightx = 0
        gbc.weighty = 0
        gbc.anchor = GridBagConstraints.NORTHWEST
        gbc.gridy = 3
        self.add(self.numberThreadsSlider, gbc)

        self.cbGenerateExcel = JCheckBox("Generate Excel format report (more detailed)", actionPerformed=self.cbGenerateExcelActionPerformed)
        self.cbGenerateExcel.setSelected(True)
        gbc.gridy = 4
        self.add(self.cbGenerateExcel, gbc)

        self.cbGenerateCSV = JCheckBox("Generate CSV format report (plaintext)", actionPerformed=self.cbGenerateCSVActionPerformed)
        self.cbGenerateCSV.setSelected(True)
        gbc.gridy = 5
        self.add(self.cbGenerateCSV, gbc)

        gbc.gridy = 6
        self.cbWayback = JCheckBox("Perform Wayback Machine Lookup on email domains (WARNING: can be a slow process!)", actionPerformed=self.cbWaybackActionPerformed)
        self.cbWayback.setSelected(True)
        self.add(self.cbWayback, gbc)

    def cbWaybackActionPerformed(self, event):
        source = event.getSource()
        if(source.isSelected()):
            ModuleSettings.setConfigSetting("FEA","doWBLookup","true")
            self.doWBLookup = True
        else:
            ModuleSettings.setConfigSetting("FEA","doNSLookup","false")
            self.doWBLookup = False

    def cbNSLookupActionPerformed(self, event):
        source = event.getSource()
        if(source.isSelected()):
            ModuleSettings.setConfigSetting("FEA","doNSLookup","true")
            self.doNSLookup = True
            self.cbWayback.setEnabled(True)
        else:
            ModuleSettings.setConfigSetting("FEA","doNSLookup","false")
            self.doNSLookup = False
            self.cbWayback.setSelected(False)
            self.cbWayback.setEnabled(False)
            self.doWBLookup = False

    def cbGenerateExcelActionPerformed(self, event):
        source = event.getSource()
        if(source.isSelected()):
            ModuleSettings.setConfigSetting("FEA","generateXLS","true")
            self.generateXLS = True
        else:
            ModuleSettings.setConfigSetting("FEA","generateXLS","false")
            self.generateXLS = False

    def cbGenerateCSVActionPerformed(self, event):
        source = event.getSource()
        if(source.isSelected()):
            ModuleSettings.setConfigSetting("FEA","generateCSV","true")
            self.generateCSV = True
        else:
            ModuleSettings.setConfigSetting("FEA","generateCSV","false")
            self.generateCSV = False

    def sliderActionPerformed(self, event):
        source = event.getSource()
        self.numThreads = source.getValue()
        ModuleSettings.setConfigSetting("FEA","numThreads",self.numThreads)
        self.addStatusLabel("number of threads set: " + str(self.numThreads))
