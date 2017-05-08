# coding: latin-1
# FEA Configuration Settings Panel
#
# João Mota (2017)
#
# Class for storing and retrieving configuration settings for the Forensic Email Analysis Report Module
# joao.lx@gmail.com
#

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

    def __init__(self):

        self.initComponents()

        if (ModuleSettings.getConfigSetting("FEA", "doNSLookup") != None) and (not ModuleSettings.getConfigSetting("FEA","doNSLookup").isEmpty()):
            if ModuleSettings.getConfigSetting("FEA","doNSLookup").equals(True):
                self.cbNSLookup.setSelected(True)
                self.doNSLookup = True
            else:
                self.cbNSLookup.setSelected(False)
                self.doNSLookup = False

        if (ModuleSettings.getConfigSetting("FEA", "generateCSV") != None) and (not ModuleSettings.getConfigSetting("FEA","generateCSV").isEmpty()):
            if ModuleSettings.getConfigSetting("FEA","generateCSV").equals(True):
                self.cbGenerateCSV.setSelected(True)
                self.generateCSV = True
            else:
                self.cbGenerateCSV.setSelected(False)
                self.generateCSV = False
        if (ModuleSettings.getConfigSetting("FEA", "generateXLS") != None) and (not ModuleSettings.getConfigSetting("FEA","generateXLS").isEmpty()):
            if ModuleSettings.getConfigSetting("FEA","generateXLS").equals(True):
                self.cbGenerateExcel.setSelected(True)
                self.generateXLS = True
            else:
                self.cbGenerateExcel.setSelected(False)
                self.generateXLS = False
        if (ModuleSettings.getConfigSetting("FEA", "numThreads") != None) and (not ModuleSettings.getConfigSetting("FEA","numThreads").isEmpty()):
            numThreads = ModuleSettings.getConfigSetting("FEA", "numThreads")
            self.numberThreadsSlider.setValue(self.numThreads)
        else:
            self.numThreads = self.numberThreadsSlider.getValue()

    def getDoNSLookup(self):
        return self.doNSLookup

    def getGenerateCSV(self):
        return self.generateCSV

    def getGenerateXLS(self):
        return self.generateXLS

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
        self.cbNSLookup = JCheckBox("Perform NSLookup on email addresses", actionPerformed=self.cbNSLookupActionPerformed)
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

    def cbNSLookupActionPerformed(event):
        source = event.getSource()
        if(source.isSelected()):
            ModuleSettings.setConfigSetting("FEA","doNSLookup","true")
            self.doNSLookup = True
        else:
            ModuleSettings.setConfigSetting("FEA","doNSLookup","false")
            self.doNSLookup = False

    def cbGenerateExcelActionPerformed(event):
        source = event.getSource()
        if(source.isSelected()):
            ModuleSettings.setConfigSetting("FEA","generateXLS","true")
            self.generateXLS = True
        else:
            ModuleSettings.setConfigSetting("FEA","generateXLS","false")
            self.generateXLS = False

    def cbGenerateCSVActionPerformed(event):
        source = event.getSource()
        if(source.isSelected()):
            ModuleSettings.setConfigSetting("FEA","generateCSV","true")
            self.generateCSV = True
        else:
            ModuleSettings.setConfigSetting("FEA","generateCSV","false")
            self.generateCSV = False

    def sliderActionPerformed(event):
        source = event.getSource()
        self.numThreads = source.getValue()
        ModuleSettings.setConfigSetting("FEA","numThreads",self.numThreads)
