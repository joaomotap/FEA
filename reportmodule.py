# coding: latin-1
# Sample module in the public domain. Feel free to use this as a template
# for your modules (and you can remove this header and take complete credit
# and liability)
#
# Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
#
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


# Sample report module for Autopsy.  Use as a starting point for new modules.
#
# See http://sleuthkit.org/autopsy/docs/api-docs/3.1/index.html for documentation

import os
import inspect
import urllib2

from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import ButtonGroup
from javax.swing import JComboBox
#from javax.swing import JRadioButton
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


class EmailCCHitsReportModule(GeneralReportModuleAdapter):

    moduleName = "FEA - Email & Credit Card Validation by Jo�o Mota - v 0.3"

    _logger = None

    def log(self, level, msg):
        if self._logger == None:
            self._logger = Logger.getLogger(self.moduleName)
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "Email and Credit Card Hit Reports"

    def getRelativeFilePath(self):
        return "FEA-JM.txt"

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

        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()

        emailArtifacts = sleuthkitCase.getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, "Email Addresses")
        ccArtifacts = sleuthkitCase.getBlackboardArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_ACCOUNT)
        progressTotal = len(emailArtifacts) + len(ccArtifacts)

        progressBar.setMaximumProgress(progressTotal + 1)

        artifactCount = 0

        # Get Blackboard artifacts
        # Emails:
        # diplay name: E-Mail Messages; ID: 13; type name: TSK_EMAIL_MSG
        # diplay name: Accounts; ID: 21; type name: TSK_SERVICE_ACCOUNT
        # diplay name: Accounts; ID: 39; type name: TSK_ACCOUNT
        # atributo para sets de keywords: TSK_SET_NAME

        # Write the results to the report file.
        fileName = os.path.join(baseReportDir, self.getRelativeFilePath())
        report = open(fileName, 'w')
        report.write("Attributes from artifacts\n")
        for artifactItem in emailArtifacts:
            for attributeItem in artifactItem.getAttributes(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD):
                email = attributeItem.getDisplayString().split(".")
                self.log(Level.INFO, "[JM] Email TLD: " + email[-1])
                if self.isTLD(email[-1]):
                    report.write("%s;\n" % attributeItem.getDisplayString())
                else:
                    self.log(Level.INFO, "[JM] that's not a valid TLD!")
            artifactCount += 1
            progressBar.increment()


        for artifactItem in ccArtifacts:
            for attributeItem in artifactItem.getAttributes(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_CARD_NUMBER):
                self.log(Level.INFO, "[JM] Credit card number: " + attributeItem.getDisplayString())
                report.write("%s;\n" % attributeItem.getDisplayString())
            artifactCount += 1
            progressBar.increment()

        report.write("Artifacts processed = %d" % artifactCount)
        report.close()
        # TODO send email notifying completion?

        # Add the report to the Case, so it is shown in the tree
        Case.getCurrentCase().addReport(fileName, self.moduleName, "Artifact Keyword Count Report");

        # last step (file write) complete
        progressBar.increment()

        # Call this with ERROR if report was not generated
        progressBar.complete(ReportStatus.COMPLETE)

    def isTLD(self, tldName):
        try:
            urllib2.urlopen("https://www.iana.org/domains/root/db/" + tldName + ".html").read()
            return True
        except urllib2.HTTPError as e:
        #self.log(Level.INFO, "[JM] caught HTTPError (not a valid TLD?)")
            return False
        return False

    # TODO: implementar l�gica no painel e tratar eventos
    def getConfigurationPanel(self):
        panel0 = JPanel(GridBagLayout())

        gbc = GridBagConstraints()
        gbc.anchor = GridBagConstraints.NORTH
        gbc.gridx = 0;
        gbc.gridy = 0;


        cbNSLookup = JCheckBox("Perform NSLookup on email addresses")

        panel0.add(cbNSLookup, gbc)

        return panel0

