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


# Email processing report module for Autopsy.
#
# See http://sleuthkit.org/autopsy/docs/api-docs/3.1/index.html for documentation

import os
import inspect
import urllib2
import java.net.InetAddress;
import java.net.UnknownHostException;

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

from threading import Thread, InterruptedException
import time


class EmailCCHitsReportModule(GeneralReportModuleAdapter):

    moduleName = "FEA - Email Validation - v 1.0"

    _logger = None

    def log(self, level, msg):
        if self._logger == None:
            self._logger = Logger.getLogger(self.moduleName)
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "Email Hit Reports"

    def getRelativeFilePath(self):
        return "FEA-emails-JM.txt"

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

        # miscellaneous initializations
        falsePositives = []
        validEmails = []
        domainNamesList = []
        invalidDomains = []
        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()
        emailArtifacts = sleuthkitCase.getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, "Email Addresses")
        progressTotal = len(emailArtifacts)     # TODO: this might be too large of a number and cause the process to freeze

        progressBar.setMaximumProgress(progressTotal + 2)

        # read valid TLD list from IANA
        try:
            req = urllib2.Request("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
            response = urllib2.urlopen(req)
            tldListHTML = response.read()
        except urllib2.HTTPError as e:
            self.log(Level.INFO, "[JM] error reading TLD list from https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
        tldListHTML.splitlines()
        progressBar.increment()

        artifactCount = 0

        # Get Blackboard artifacts
        # Emails:
        # display name: E-Mail Messages; ID: 13; type name: TSK_EMAIL_MSG
        # display name: Accounts; ID: 21; type name: TSK_SERVICE_ACCOUNT
        # display name: Accounts; ID: 39; type name: TSK_ACCOUNT
        # atributo para sets de keywords: TSK_SET_NAME

        for artifactItem in emailArtifacts:
            for attributeItem in artifactItem.getAttributes(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD):
                email = attributeItem.getDisplayString().split(".")
                #self.log(Level.INFO, "[JM] Email TLD: " + email[-1])
                if email[-1].upper() in tldListHTML:
                    if not(attributeItem.getDisplayString() in validEmails):
                        validEmails.append(attributeItem.getDisplayString())
                    domain = attributeItem.getDisplayString().split("@")
                    self.log(Level.INFO, "[JM] Email domain name: " + domain[-1])
                    if not(domain[-1] in domainNamesList):
                        domainNamesList.append(domain[-1])
                else:
                    #self.log(Level.INFO, "[JM] that's not a valid TLD!")
                    if not(attributeItem.getDisplayString() in falsePositives):
                        falsePositives.append(attributeItem.getDisplayString())
            artifactCount += 1
            progressBar.increment()

        #TODO get config setting before checking NSLookup
        #JPanel configPanel = self.getConfigurationPanel()

        for i in domainNamesList:
            try:
                inetHost = java.net.InetAddress.getByName(i)
                hostName = inetHost.getHostName()
                #self.log(Level.INFO, "[JM] Domain name lookup - hostname: " + hostName)
            except java.net.UnknownHostException as e:
                domainNamesList.remove(i)
                if not(i in invalidDomains):
                    invalidDomains.append(i)
                #self.log(Level.INFO, "[JM] Uknown host: " + i)
        for i in validEmails:
            domainCheck = i.split("@")
            if domainCheck[-1] in invalidDomains:
                validEmails.remove(i)
                falsePositives.append(i)

        # Write the results to the report file.
        fileName = os.path.join(baseReportDir, self.getRelativeFilePath())
        report = open(fileName, 'w')
        report.write("Valid emails:\n")
        for i in validEmails:
            report.write("%s\n" % i)

        report.write("False positives:\n")
        for i in falsePositives:
            report.write("%s\n" % i)

        report.write("Valid distinct domain names:\n")
        for i in domainNamesList:
            report.write("%s\n" % i)

        report.write("Total artifacts processed = %d\n" % artifactCount)
        report.close()

        # Add the report to the Case, so it is shown in the tree
        Case.getCurrentCase().addReport(fileName, self.moduleName, "Artifact Keyword Count Report");

        # last step (file write) complete
        progressBar.increment()

        # Call this with ERROR if report was not generated
        progressBar.complete(ReportStatus.COMPLETE)


    # *******************************************************************
    # * Function: check if domain is valid by performing NSLookup on it *
    # *******************************************************************
    class DomainLookup(Thread):

        def isValidDomain(self, domainName):
            try:
                inetHost = java.net.InetAddress.getByName(i)
                hostName = inetHost.getHostName()
                #self.log(Level.INFO, "[JM] Domain name lookup - hostname: " + hostName)
                return True
            except java.net.UnknownHostException as e:
                return False

    # *******************************************
    # * Function: implement config settings GUI *
    # *******************************************

    def getConfigurationPanel(self):
        # TODO: implementar lógica no painel e tratar eventos
        panel0 = JPanel(GridBagLayout())

        gbc = GridBagConstraints()
        gbc.anchor = GridBagConstraints.NORTHEAST
        gbc.gridx = 0
        gbc.gridy = 0


        cbNSLookup = JCheckBox("Perform NSLookup on email addresses")
        panel0.add(cbNSLookup, gbc)

        blacklistLabel = JLabel("Email addresses to excluded (blacklist):")
        gbc.gridy = 1
        panel0.add(blacklistLabel, gbc)

        blacklistTextArea = JTextArea()
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.gridy = 2
        gbc.ipady = 40
        panel0.add(blacklistTextArea, gbc)

        cbRefreshCache = JCheckBox("Refresh domain lookup cache")
        gbc.gridy = 3
        gbc.ipady = 1
        panel0.add(cbRefreshCache, gbc)

        return panel0

