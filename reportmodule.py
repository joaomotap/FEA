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
import java.net.InetAddress
import java.net.UnknownHostException
import time
import re
import xlwt

#from jm_reporting import EmailReport

from threading import Thread
from Queue import Queue
from jm_domain_lookup import DomainLookupTask

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

    moduleName = "FEA - Email Validation - v 1.0"
    
    # maximum number of concurrent threads to launch (used in domain lookup process)
    MAX_THREADS = 8

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
        return "FEA-Email_Validation_Report.csv"

    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, baseReportDir, progressBar):


        #   /$$$$$$           /$$   /$$             
        #  |_  $$_/          |__/  | $$             
        #    | $$   /$$$$$$$  /$$ /$$$$$$   /$$$$$$$
        #    | $$  | $$__  $$| $$|_  $$_/  /$$_____/
        #    | $$  | $$  \ $$| $$  | $$   |  $$$$$$ 
        #    | $$  | $$  | $$| $$  | $$ /$$\____  $$
        #   /$$$$$$| $$  | $$| $$  |  $$$$//$$$$$$$/
        #  |______/|__/  |__/|__/   \___/ |_______/ 
        #                                           
        #                                           
        #                                           

        self.log(Level.INFO, "*****************************************************")
        self.log(Level.INFO, "* [JM] Scraping artifacts from blackboard starting  *")
        self.log(Level.INFO, "*****************************************************")
        
        progressBar.updateStatusLabel("Initializing")

        # configure progress bar
        progressBar.setIndeterminate(False)
        progressBar.start()

        # miscellaneous initializations
        reportDB = self.EmailReport()
        count = 0
        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()
        emailArtifacts = sleuthkitCase.getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, "Email Addresses")
        progressTotal = len(emailArtifacts)     # TODO: this might be too large of a number and cause the process to freeze

        progressBar.setMaximumProgress(progressTotal * 2 + 2)

        # read valid TLD list from IANA
        progressBar.updateStatusLabel("Retrieving udpated list of valid TLDs from iana.org")
        try:
            req = urllib2.Request("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
            response = urllib2.urlopen(req)
            tldListHTML = response.read()
        except urllib2.HTTPError as e:
            self.log(Level.INFO, "[JM] error reading TLD list from https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
        tldListHTML.splitlines()
        progressBar.increment()


        # Create Excel Workbook
        fileNameExcel = os.path.join(baseReportDir, "teste.xls")
        book = xlwt.Workbook(encoding="utf-8")
        sheetDomains = book.add_sheet("Interesting domains")
        sheetFalsePositives = book.add_sheet("False Positives")
        styleRowHeaders = xlwt.easyxf('font: name Arial, color-index blue, bold on', num_format_str='#,##0.00')
        sheetFalsePositives.write(0,0,"Email", styleRowHeaders)
        sheetFalsePositives.write(0,1,"Alphanumeric check", styleRowHeaders)
        sheetFalsePositives.write(0,2,"TLD", styleRowHeaders)
        sheetFalsePositives.write(0,3,"TLD check", styleRowHeaders)
        sheetFalsePositives.write(0,4,"Domain", styleRowHeaders)
        sheetFalsePositives.write(0,5,"Domain check", styleRowHeaders)
        sheetFalsePositives.write(0,6,"Internet archive check", styleRowHeaders)
        sheetDomains.write(0,0,"Domain name", styleRowHeaders)
        sheetDomains.write(0,1,"Hits", styleRowHeaders)


        # Open report file for writing
        fileName = os.path.join(baseReportDir, self.getRelativeFilePath())
        report = open(fileName, 'w')

        # write csv header row
        report.write("artifact email;Alphanumeric check;TLD;TLD check;domain;domain check;internet archive check\n")


        #    /$$$$$$              /$$            /$$$$$$              /$$     /$$  /$$$$$$                      /$$             
        #   /$$__  $$            | $$           /$$__  $$            | $$    |__/ /$$__  $$                    | $$             
        #  | $$  \__/  /$$$$$$  /$$$$$$        | $$  \ $$  /$$$$$$  /$$$$$$   /$$| $$  \__//$$$$$$   /$$$$$$$ /$$$$$$   /$$$$$$$
        #  | $$ /$$$$ /$$__  $$|_  $$_/        | $$$$$$$$ /$$__  $$|_  $$_/  | $$| $$$$   |____  $$ /$$_____/|_  $$_/  /$$_____/
        #  | $$|_  $$| $$$$$$$$  | $$          | $$__  $$| $$  \__/  | $$    | $$| $$_/    /$$$$$$$| $$        | $$   |  $$$$$$ 
        #  | $$  \ $$| $$_____/  | $$ /$$      | $$  | $$| $$        | $$ /$$| $$| $$     /$$__  $$| $$        | $$ /$$\____  $$
        #  |  $$$$$$/|  $$$$$$$  |  $$$$/      | $$  | $$| $$        |  $$$$/| $$| $$    |  $$$$$$$|  $$$$$$$  |  $$$$//$$$$$$$/
        #   \______/  \_______/   \___/        |__/  |__/|__/         \___/  |__/|__/     \_______/ \_______/   \___/ |_______/ 
        #                                                                                                                       
        #                                                                                                                       
        #                                                                                                                       
        # Get Blackboard artifacts
        # Emails:
        # display name: E-Mail Messages; ID: 13; type name: TSK_EMAIL_MSG
        # display name: Accounts; ID: 21; type name: TSK_SERVICE_ACCOUNT
        # display name: Accounts; ID: 39; type name: TSK_ACCOUNT
        # atributo para sets de keywords: TSK_SET_NAME
        
        progressBar.updateStatusLabel("Retrieving emails from Autopsy blackboard")

        for artifactItem in emailArtifacts:

            for attributeItem in artifactItem.getAttributes(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD):
                count += 1
                tldFlag = False

                email = attributeItem.getDisplayString().split(".")

                if email[-1].upper() in tldListHTML:
                    tldFlag = True

                reportDB.addEmailRecord(count, attributeItem.getDisplayString(), tldCheck=tldFlag)
                if tldFlag:
                    self.log(Level.INFO, "[JM] adding record to report. Count = " + str(count) + "; email = " + attributeItem.getDisplayString() + "; tldCheck = True")
                else:
                    self.log(Level.INFO, "[JM] adding record to report. Count = " + str(count) + "; email = " + attributeItem.getDisplayString() + "; tldCheck = False")

            progressBar.increment()



        #   /$$$$$$$  /$$   /$$  /$$$$$$        /$$                           /$$                          
        #  | $$__  $$| $$$ | $$ /$$__  $$      | $$                          | $$                          
        #  | $$  \ $$| $$$$| $$| $$  \__/      | $$        /$$$$$$   /$$$$$$ | $$   /$$ /$$   /$$  /$$$$$$ 
        #  | $$  | $$| $$ $$ $$|  $$$$$$       | $$       /$$__  $$ /$$__  $$| $$  /$$/| $$  | $$ /$$__  $$
        #  | $$  | $$| $$  $$$$ \____  $$      | $$      | $$  \ $$| $$  \ $$| $$$$$$/ | $$  | $$| $$  \ $$
        #  | $$  | $$| $$\  $$$ /$$  \ $$      | $$      | $$  | $$| $$  | $$| $$_  $$ | $$  | $$| $$  | $$
        #  | $$$$$$$/| $$ \  $$|  $$$$$$/      | $$$$$$$$|  $$$$$$/|  $$$$$$/| $$ \  $$|  $$$$$$/| $$$$$$$/
        #  |_______/ |__/  \__/ \______/       |________/ \______/  \______/ |__/  \__/ \______/ | $$____/ 
        #                                                                                        | $$      
        #                                                                                        | $$      
        #                                                                                        |__/      

        #TODO get config setting before checking NSLookup
        #JPanel configPanel = self.getConfigurationPanel()


        #*******************************************************
        #* Domain Name Lookup - Multithreaded                  *
        #*******************************************************

        progressBar.updateStatusLabel("Verifying valid domains in email addresses")
        
        q_in = Queue()
        q_out_valid = Queue()
        q_out_invalid = Queue()
        for url in reportDB.getListOfDomains():
            q_in.put(url, block = True, timeout = 5)
            #self.log(Level.INFO, "[JM] Adding domain to thread queue: " + url)
        
        self.log(Level.INFO, "[JM] Starting domain lookup threads")
        
        thread_pool = list()
        for i in range(self.MAX_THREADS):
            t = DomainLookupTask(q_in, q_out_valid, q_out_invalid)
            t.start()
            thread_pool.append(t)
        
        for t in thread_pool:
            progressBar.increment()
            t.join()
        
        while not q_out_valid.empty():
            url = q_out_valid.get()
            reportDB.setDomains(url, True)
            #self.log(Level.INFO, "[JM] Valid domain found: " + url)
            
        while not q_out_invalid.empty():
            url = q_out_invalid.get()
            #self.log(Level.INFO, "[JM] Invalid domain found: " + url)
            reportDB.setDomains(url, False)


        #   /$$      /$$           /$$   /$$                     /$$$$$$$                                            /$$    
        #  | $$  /$ | $$          |__/  | $$                    | $$__  $$                                          | $$    
        #  | $$ /$$$| $$  /$$$$$$  /$$ /$$$$$$    /$$$$$$       | $$  \ $$  /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$  /$$$$$$  
        #  | $$/$$ $$ $$ /$$__  $$| $$|_  $$_/   /$$__  $$      | $$$$$$$/ /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$|_  $$_/  
        #  | $$$$_  $$$$| $$  \__/| $$  | $$    | $$$$$$$$      | $$__  $$| $$$$$$$$| $$  \ $$| $$  \ $$| $$  \__/  | $$    
        #  | $$$/ \  $$$| $$      | $$  | $$ /$$| $$_____/      | $$  \ $$| $$_____/| $$  | $$| $$  | $$| $$        | $$ /$$
        #  | $$/   \  $$| $$      | $$  |  $$$$/|  $$$$$$$      | $$  | $$|  $$$$$$$| $$$$$$$/|  $$$$$$/| $$        |  $$$$/
        #  |__/     \__/|__/      |__/   \___/   \_______/      |__/  |__/ \_______/| $$____/  \______/ |__/         \___/  
        #                                                                           | $$                                    
        #                                                                           | $$                                    
        #                                                                           |__/                                    

        #*******************************************************
        #* Write report to file                                *
        #*******************************************************

        progressBar.updateStatusLabel("Writing report to file")

        for row in reportDB.getReportRows():
            report.write(row)
            report.write("\n")

        report.close()

        baseCell = 1
        for rec in reportDB.getListOfValidDomains():
            sheetDomains.write(baseCell, 0, rec)
            baseCell += 1

        book.save(fileNameExcel)
        Case.getCurrentCase().addReport(fileNameExcel, self.moduleName, "FEA - Email Validation Report (eXcel)")

        # Add the report to the Case, so it is shown in the tree
        Case.getCurrentCase().addReport(fileName, self.moduleName, "Artifact Keyword Count Report");

        # last step (file write) complete
        progressBar.increment()

        # Call this with ERROR if report was not generated
        progressBar.complete(ReportStatus.COMPLETE)


    #    /$$$$$$                       /$$$$$$  /$$                  /$$$$$$  /$$   /$$ /$$$$$$
    #   /$$__  $$                     /$$__  $$|__/                 /$$__  $$| $$  | $$|_  $$_/
    #  | $$  \__/  /$$$$$$  /$$$$$$$ | $$  \__/ /$$  /$$$$$$       | $$  \__/| $$  | $$  | $$  
    #  | $$       /$$__  $$| $$__  $$| $$$$    | $$ /$$__  $$      | $$ /$$$$| $$  | $$  | $$  
    #  | $$      | $$  \ $$| $$  \ $$| $$_/    | $$| $$  \ $$      | $$|_  $$| $$  | $$  | $$  
    #  | $$    $$| $$  | $$| $$  | $$| $$      | $$| $$  | $$      | $$  \ $$| $$  | $$  | $$  
    #  |  $$$$$$/|  $$$$$$/| $$  | $$| $$      | $$|  $$$$$$$      |  $$$$$$/|  $$$$$$/ /$$$$$$
    #   \______/  \______/ |__/  |__/|__/      |__/ \____  $$       \______/  \______/ |______/
    #                                               /$$  \ $$                                  
    #                                              |  $$$$$$/                                  
    #                                               \______/                                   
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

        blacklistLabel = JLabel("Email addresses to be excluded (blacklist):")
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

        cbGenerateExcel = JCheckBox("Generate Excel format report (more detailed)")
        gbc.gridy = 4
        panel0.add(cbGenerateExcel, gbc)

        cbGenerateCSV = JCheckBox("Generate CSV format report (plaintext)")
        gbc.gridy = 5
        panel0.add(cbGenerateCSV, gbc)

        return panel0

    #   /$$$$$$$                                            /$$            /$$$$$$  /$$                             
    #  | $$__  $$                                          | $$           /$$__  $$| $$                             
    #  | $$  \ $$  /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$  /$$$$$$        | $$  \__/| $$  /$$$$$$   /$$$$$$$ /$$$$$$$
    #  | $$$$$$$/ /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$|_  $$_/        | $$      | $$ |____  $$ /$$_____//$$_____/
    #  | $$__  $$| $$$$$$$$| $$  \ $$| $$  \ $$| $$  \__/  | $$          | $$      | $$  /$$$$$$$|  $$$$$$|  $$$$$$ 
    #  | $$  \ $$| $$_____/| $$  | $$| $$  | $$| $$        | $$ /$$      | $$    $$| $$ /$$__  $$ \____  $$\____  $$
    #  | $$  | $$|  $$$$$$$| $$$$$$$/|  $$$$$$/| $$        |  $$$$/      |  $$$$$$/| $$|  $$$$$$$ /$$$$$$$//$$$$$$$/
    #  |__/  |__/ \_______/| $$____/  \______/ |__/         \___/         \______/ |__/ \_______/|_______/|_______/ 
    #                      | $$                                                                                     
    #                      | $$                                                                                     
    #                      |__/                                                                                         
    # ***********************************************************************
    # * EMAIL REPORT inner class                                            *
    # *                                                                     *
    # * Maintains full list of email in a dict structure comprised of       *
    # * EmailRecord class objects                                           *
    # *                                                                     *
    # ***********************************************************************

    class EmailReport(object):

        def __init__(self):
            self.recordList = {}
            self.recordCount = 0

        def addEmailRecord(self, id, email, tldCheck=None, domainCheck=None):
            self.recordCount += 1
            newRecord = self.EmailRecord(email.lower(), tldCheck, domainCheck)
            self.recordList[id] = newRecord

        def getRecordById(self, id):
            return self.recordList.get(id, default=None)

        def getAllRecords(self):
            return self.recordList.values()

        def getTotalRecords(self):
            return self.recordCount

        def getListOfDomains(self):
            domainNamesList = []
            for rec in self.recordList.values():
                if not(rec.getDomain() in domainNamesList):
                    domainNamesList.append(rec.getDomain())
            return domainNamesList

        def getListOfValidDomains(self):
            domainNamesList = []
            for rec in self.recordList.values():
                if not(rec.getDomain() in domainNamesList):
                    if rec.tldCheck and rec.domainCheck:
                        domainNamesList.append(rec.getDomain())
            return domainNamesList

        def setDomains(self, domain, lookup):
            for rec in self.recordList.values():
                if rec.getDomain() == domain:
                    rec.setDomainCheck(lookup)

        def updateDomainCheck(self, id, domainCheck):
            self.recordList[id].setDomainCheck(domainCheck)

        def getReportRows(self):
            for r in self.recordList.values():
                yield r.getEmailReportRow()

        class EmailRecord(object):
            def __init__(self, email, tldCheck, domainCheck):
                self.email = email
                self.tldCheck = tldCheck
                self.domainCheck = domainCheck

            def setDomainCheck(self, domainCheck):
                self.domainCheck = domainCheck

            def getDomain(self):
                domain = self.email.split("@")
                return domain[-1].lower()

            def getTLD(self):
                return self.email.split(".")[-1]

            def getEmailReportRow(self):
                alphaCheck = "Ok"
                tldRes = "Failed"
                domainRes = "Failed"
                if (re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', self.email.lower()) == None):
                    alphaCheck = "Failed"
                if self.tldCheck:
                    tldRes = "Ok"
                if self.domainCheck:
                    domainRes = "Ok"
                return self.email + ";" + alphaCheck + ";" + self.getDomain() + ";" + self.getTLD() + ";" + tldRes + ";" + domainRes

