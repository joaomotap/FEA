# coding: latin-1
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.


# Credit card analysis report module for Autopsy.
#
# by João Mota

import os
import inspect
import urllib2
import xlwt

from java.lang import Class
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import TagsManager
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute

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


class CCHitsReportModule(GeneralReportModuleAdapter):

    moduleName = "FEA - Credit Card Validation"

    _logger = None

    def log(self, level, msg):
        if self._logger == None:
            self._logger = Logger.getLogger(self.moduleName)
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "Credit Card Hit Reports"

    def getRelativeFilePath(self):
        return "FEA-CC-JM.csv"

    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, baseReportDir, progressBar):

        self.log(Level.INFO, "*****************************************************")
        self.log(Level.INFO, "* [JM] Scraping artifacts from blackboard starting  *")
        self.log(Level.INFO, "*****************************************************")

        # configure progress bar
        progressBar.setIndeterminate(False)
        progressBar.start()

        # read GUI config settings
        generateXLS = self.configPanel.getGenerateXLS()
        generateCSV = self.configPanel.getGenerateCSV()
        removeFalsePositives = self.configPanel.getRemoveFalsePositives()

        # Create Excel Workbook
        if generateXLS:
            baseCell = 0
            fileNameExcel = os.path.join(baseReportDir, Case.getCurrentCase().getName() + "_CC_FEA.xls")
            book = xlwt.Workbook(encoding="utf-8")
            sheetFalsePositives = book.add_sheet("Autopsy Credit Cards")
            styleRowHeaders = xlwt.easyxf('font: name Arial, color-index blue, bold on', num_format_str='#,##0.00')
            sheetFalsePositives.write(0,0,"Card Number", styleRowHeaders)
            sheetFalsePositives.write(0,1,"Valid", styleRowHeaders)
            sheetFalsePositives.write(0,2,"Source", styleRowHeaders)

        # Open report CSV file for writing
        if generateCSV:
            fileName = os.path.join(baseReportDir, self.getRelativeFilePath())
            report = open(fileName, 'w')

            # write csv header row
            report.write("card number;valid;source\n")

        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()

        ccArtifacts = sleuthkitCase.getBlackboardArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_ACCOUNT)
        progressTotal = len(ccArtifacts)

        progressBar.setMaximumProgress(progressTotal + 1)

        artifactCount = 0

        # Get Blackboard artifacts
        # Emails:
        # display name: E-Mail Messages; ID: 13; type name: TSK_EMAIL_MSG
        # display name: Accounts; ID: 21; type name: TSK_SERVICE_ACCOUNT
        # display name: Accounts; ID: 39; type name: TSK_ACCOUNT
        # atributo para sets de keywords: TSK_SET_NAME

        for artifactItem in ccArtifacts:
            for attributeItem in artifactItem.getAttributes(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_CARD_NUMBER):
                ccNumber = attributeItem.getDisplayString()
                self.log(Level.INFO, "[JM] Credit card number: " + ccNumber)
                sourceFiles = sleuthkitCase.findAllFilesWhere("obj_id = " + str(attributeItem.getParentArtifact().getObjectID()))
                sourceFile = ""
                for file in sourceFiles:
                    if sourceFile == "":
                        sourceFile = file.getName()
                    else:
                        sourceFile = sourceFile + " & " + file.getName()

                valid = True
                if self.is_luhn_valid(ccNumber):
                    self.log(Level.INFO, "[JM] CC is valid")
                else:
                    self.log(Level.INFO, "[JM] CC is NOT valid")
                    valid = False
                if generateXLS:
                    baseCell += 1
                    sheetFalsePositives.write(baseCell,0, ccNumber)
                    if valid:
                        sheetFalsePositives.write(baseCell,1, "Valid")
                    else:
                        sheetFalsePositives.write(baseCell,1, "Not Valid")
                    sheetFalsePositives.write(baseCell,2,sourceFile)
                if generateCSV:
                    if valid:
                        report.write("%s;Valid\n" % ccNumber)
                    else:
                        report.write("%s;Not Valid\n" % ccNumber)
            artifactCount += 1
            progressBar.increment()
        if generateCSV:
            report.close()
            Case.getCurrentCase().addReport(fileName, self.moduleName, "Artifact Keyword Count Report")
        if generateXLS:
            book.save(fileNameExcel)
            Case.getCurrentCase().addReport(fileNameExcel, self.moduleName, "FEA - Email Validation Report (eXcel)")

        # last step (file write) complete
        progressBar.increment()

        # Call this with ERROR if report was not generated
        progressBar.complete(ReportStatus.COMPLETE)



#   /$$                 /$$                
#  | $$                | $$                
#  | $$       /$$   /$$| $$$$$$$  /$$$$$$$ 
#  | $$      | $$  | $$| $$__  $$| $$__  $$
#  | $$      | $$  | $$| $$  \ $$| $$  \ $$
#  | $$      | $$  | $$| $$  | $$| $$  | $$
#  | $$$$$$$$|  $$$$$$/| $$  | $$| $$  | $$
#  |________/ \______/ |__/  |__/|__/  |__/
#                                          
#                                          
#                                          

    def digits_of(self, number):
        return [int(i) for i in str(number)]

    def luhn_checksum(self, card_number):
        digits = self.digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        total = sum(odd_digits)
        for digit in even_digits:
            total += sum(self.digits_of(2 * digit))
        return total % 10

    def is_luhn_valid(self, card_number):
        return self.luhn_checksum(card_number) == 0


#    /$$$$$$                       /$$$$$$  /$$                  /$$$$$$  /$$   /$$ /$$
#   /$$__  $$                     /$$__  $$|__/                 /$$__  $$| $$  | $$|__/
#  | $$  \__/  /$$$$$$  /$$$$$$$ | $$  \__/ /$$  /$$$$$$       | $$  \__/| $$  | $$ /$$
#  | $$       /$$__  $$| $$__  $$| $$$$    | $$ /$$__  $$      | $$ /$$$$| $$  | $$| $$
#  | $$      | $$  \ $$| $$  \ $$| $$_/    | $$| $$  \ $$      | $$|_  $$| $$  | $$| $$
#  | $$    $$| $$  | $$| $$  | $$| $$      | $$| $$  | $$      | $$  \ $$| $$  | $$| $$
#  |  $$$$$$/|  $$$$$$/| $$  | $$| $$      | $$|  $$$$$$$      |  $$$$$$/|  $$$$$$/| $$
#   \______/  \______/ |__/  |__/|__/      |__/ \____  $$       \______/  \______/ |__/
#                                               /$$  \ $$                              
#                                              |  $$$$$$/                              
#                                               \______/                               

    # *******************************************
    # * Function: implement config settings GUI *
    # *******************************************
    def getConfigurationPanel(self):
        self.configPanel = FEA_CC_ConfigPanel()
        return self.configPanel



class FEA_CC_ConfigPanel(JPanel):

    # cbNSLookup = JCheckBox()
    # cbGenerateCSV = JCheckBox()
    # cbGenerateExcel = JCheckBox()
    # numberThreadsSlider = JSlider()
    
    generateXLS = True
    generateCSV = True
    removeFalsePositives = True
    cbRemoveFalsePositives = None
    cbGenerateExcel = None
    cbGenerateCSV = None
    
    def __init__(self):

        self.initComponents()
        
        # get previous settings selected by the user

        if (ModuleSettings.getConfigSetting("FEA", "removeFalsePositives") != None) and (ModuleSettings.getConfigSetting("FEA","removeFalsePositives") != ""):
            if ModuleSettings.getConfigSetting("FEA","removeFalsePositives"):
                self.cbRemoveFalsePositives.setSelected(True)
                self.removeFalsePositives = True
            else:
                self.cbRemoveFalsePositives.setSelected(False)
                self.removeFalsePositives = False
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

    def addStatusLabel(self, msg):
            gbc = GridBagConstraints()
            gbc.anchor = GridBagConstraints.NORTHWEST
            gbc.gridx = 0
            gbc.gridy = 7
            lab = JLabel(msg)
            self.add(lab, gbc)

    def getGenerateCSV(self):
        return self.generateCSV

    def getGenerateXLS(self):
        return self.generateXLS

    def getRemoveFalsePositives(self):
        return self.removeFalsePositives

    def initComponents(self):
        self.setLayout(GridBagLayout())

        gbc = GridBagConstraints()
        gbc.anchor = GridBagConstraints.NORTHWEST
        gbc.gridx = 0
        gbc.gridy = 0

        descriptionLabel = JLabel("FEA - Credit Card module")
        self.add(descriptionLabel, gbc)

        self.cbGenerateExcel = JCheckBox("Generate Excel format report (more detailed)", actionPerformed=self.cbGenerateExcelActionPerformed)
        self.cbGenerateExcel.setSelected(True)
        gbc.gridy = 2
        self.add(self.cbGenerateExcel, gbc)

        self.cbGenerateCSV = JCheckBox("Generate CSV format report (plaintext)", actionPerformed=self.cbGenerateCSVActionPerformed)
        self.cbGenerateCSV.setSelected(True)
        gbc.gridy = 3
        self.add(self.cbGenerateCSV, gbc)

        self.cbRemoveFalsePositives = JCheckBox("Remove False Positives from Autopsy", actionPerformed=self.cbRemoveFalsePositivesActionPerformed)
        self.cbRemoveFalsePositives.setSelected(True)
        gbc.gridy = 4
        self.cbRemoveFalsePositives.setEnabled(False)
        self.add(self.cbRemoveFalsePositives, gbc)


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

    def cbRemoveFalsePositivesActionPerformed(self, event):
        source = event.getSource()
        if(source.isSelected()):
            ModuleSettings.setConfigSetting("FEA","removeFalsePositives","true")
            self.removeFalsePositives = True
        else:
            ModuleSettings.setConfigSetting("FEA","removeFalsePositives","false")
            self.removeFalsePositives = False

