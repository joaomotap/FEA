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
# by João Mota

import os
import inspect
import urllib2
import java.net.InetAddress
import java.net.UnknownHostException
import time
import re
import xlwt
import json

#from jm_reporting import EmailReport

from threading import Thread
from Queue import Queue
from jm_domain_lookup import DomainLookupTask
from jm_fea_config_panel import FEA_ConfigPanel

from java.lang import Class
from java.lang import System
from java.util.logging import Level
from javax.swing import JPanel

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import TagsManager
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import ModuleSettings
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report import DefaultReportConfigurationPanel
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute



class EmailCCHitsReportModule(GeneralReportModuleAdapter):

    moduleName = "FEA - Email Validation - v 1.0"
    
    # maximum number of concurrent threads to launch (used in domain lookup process)
    MAX_THREADS = 8

    _logger = None

    configPanel = FEA_ConfigPanel()

    def log(self, level, msg):
        if self._logger == None:
            self._logger = Logger.getLogger(self.moduleName)
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "Email Hit Reports"

    def getRelativeFilePath(self):
        return Case.getCurrentCase().getName() + "_FEA.csv"


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

        self.log(Level.INFO, "[JM] Reading config settings")
        MAX_THREADS = self.configPanel.getNumThreads()
        self.log(Level.INFO, "[JM] Number of threads for DNS Lookup = " + str(MAX_THREADS))

        generateXLS = self.configPanel.getGenerateXLS()
        generateCSV = self.configPanel.getGenerateCSV()
        doNSLookup = self.configPanel.getDoNSLookup()
        doWBLookup = self.configPanel.getDoWBLookup()

        # miscellaneous initializations
        progressBar.updateStatusLabel("Retrieving udpated list of valid TLDs from iana.org")
        reportDB = self.EmailReport()
        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()
        emailArtifacts = sleuthkitCase.getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, "Email Addresses")
        progressTotal = len(emailArtifacts)     # TODO: this might be too large of a number and cause the process to freeze

        progressBar.setMaximumProgress(progressTotal * 2 + 2)

        progressBar.increment()


        # Create Excel Workbook
        if generateXLS:
            fileNameExcel = os.path.join(baseReportDir, Case.getCurrentCase().getName() + "_FEA.xls")
            book = xlwt.Workbook(encoding="utf-8")
            sheetDomains = book.add_sheet("Interesting domains")
            sheetFalsePositives = book.add_sheet("Detail")
            sheetTruePositives = book.add_sheet("Valid Emails")
            styleRowHeaders = xlwt.easyxf('font: name Arial, color-index blue, bold on', num_format_str='#,##0.00')
            sheetFalsePositives.write(0,0,"Email", styleRowHeaders)
            sheetFalsePositives.write(0,1,"Alphanumeric check", styleRowHeaders)
            sheetFalsePositives.write(0,2,"TLD", styleRowHeaders)
            sheetFalsePositives.write(0,3,"TLD check", styleRowHeaders)
            sheetFalsePositives.write(0,4,"Domain", styleRowHeaders)
            sheetFalsePositives.write(0,5,"Domain Checked?", styleRowHeaders)
            sheetFalsePositives.write(0,6,"Domain check", styleRowHeaders)
            sheetFalsePositives.write(0,7,"Internet archive check", styleRowHeaders)
            sheetDomains.write(0,0,"Domain name", styleRowHeaders)
            sheetDomains.write(0,1,"Hits", styleRowHeaders)
            sheetTruePositives.write(0,0,"Email", styleRowHeaders)
            sheetTruePositives.write(0,1,"Source", styleRowHeaders)


        # Open report file for writing
        if generateCSV:
            fileName = os.path.join(baseReportDir, self.getRelativeFilePath())
            report = open(fileName, 'w')

            # write csv header row
            report.write("artifact email;Alphanumeric check;TLD;TLD check;domain;domain checked?;domain check;internet archive check\n")


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
        # attribute for sets of keywords: TSK_SET_NAME
        
        progressBar.updateStatusLabel("Retrieving emails from the Autopsy blackboard")

        #self.log(Level.INFO, "List of TLDs:\n" + tldListHTML)

        for artifactItem in emailArtifacts:

            for attributeItem in artifactItem.getAttributes(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD):
                reportDB.addNewEmailRecord(attributeItem.getDisplayString())

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
        
        if doNSLookup:
            q_in = Queue()
            q_out_valid = Queue()
            q_out_invalid = Queue()
            for url in reportDB.getListOfUniqueDomains():
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
                if doWBLookup:
                    progressBar.updateStatusLabel("Cross-checking invalid domain in the Wayback Machine (" + url + ")")
                    reportDB.setWayback(url)
                progressBar.increment()


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

        progressBar.updateStatusLabel("Writing report to file (if any reports selected)")

        baseCell = 1
        
        for row in reportDB.getUniqueReportRows():
            if generateCSV:
                report.write(row)
                report.write("\n")
            if generateXLS:
                items = row.split(";")
                # TODO: remove hardcoded range size to allow for future error-free updates to report columns
                for n in range(8):
                    sheetFalsePositives.write(baseCell,n,items[n])
            baseCell += 1

        if generateXLS:
            baseCell = 1
            for rec in reportDB.getListOfValidDomains():
                sheetDomains.write(baseCell, 0, rec)
                sheetDomains.write(baseCell, 1, reportDB.getHitsForDomain(rec))
                baseCell += 1

            baseCell = 1
            for rec in reportDB.getListOfValidEmailAddresses():
                sheetTruePositives.write(baseCell,0,rec)
                # TODO write SOURCE of valid email address!
                baseCell += 1

            book.save(fileNameExcel)
            Case.getCurrentCase().addReport(fileNameExcel, self.moduleName, "FEA - Email Validation Report (eXcel)")

        # Add the report to the Case, so it is shown in the tree
        if generateCSV:
            report.close()
            Case.getCurrentCase().addReport(fileName, self.moduleName, "FEA - Email Validation Report (CSV)");

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
        
        self.configPanel = FEA_ConfigPanel()
        return self.configPanel



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

        IANA_ADDR = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

        def __init__(self):
            self.recordList = {}
            self.recordCount = 0
            # read valid TLD list from IANA
            try:
                req = urllib2.Request(self.IANA_ADDR)
                response = urllib2.urlopen(req)
                tldListHTML = response.read()
            except urllib2.HTTPError as e:
                raise ValueError("error accessing TLD list from " + self.IANA_ADDR)
            self.tldList = tldListHTML.splitlines()

        def addEmailRecord(self, newEmailRecord):
            self.recordCount += 1
            self.recordList[recordCount] = newEmailRecord
        def addNewEmailRecord(self, email, tldCheck=None, domainCheck=None):
            newRecord = self.EmailRecord(email.lower(), tldCheck, domainCheck, False)
            newRecord.checkTLD(self.tldList)
            newRecord.checkAlpha()
            self.recordList[self.recordCount] = newRecord
            self.recordCount += 1

        def getRecordById(self, id):
            return self.recordList.get(id, default=None)

        def getAllRecords(self):
            return self.recordList.values()

        def getTotalRecords(self):
            return self.recordCount

        def getListOfUniqueDomains(self):
            # returns list of de-duped list of domains with valid TLDs
            domainNamesList = []
            for rec in self.recordList.values():
                if not(rec.getDomain() in domainNamesList) and rec.getTLDCheck():
                    domainNamesList.append(rec.getDomain())
            return domainNamesList

        def getListOfValidDomains(self):
            domainNamesList = []
            for rec in self.recordList.values():
                if not(rec.getDomain() in domainNamesList):
                    if rec.getTLDCheck() and rec.domainCheck:
                        domainNamesList.append(rec.getDomain())
            return domainNamesList

        def getListOfValidEmailAddresses(self):
            validEmailsList = []
            for rec in self.recordList.values():
                if not(rec.getEmail() in validEmailsList):
                    if rec.getTLDCheck() and rec.getAlphaCheck():
                        validEmailsList.append(rec.getEmail())
            return validEmailsList

        def getHitsForDomain(self, domain):
            count = 0
            for rec in self.recordList.values():
                if rec.getDomain() == domain:
                    count += 1
            return count

        def setDomains(self, domain, lookup):
            for rec in self.recordList.values():
                if rec.getDomain() == domain:
                    rec.setDomainCheck(lookup)

        def setWayback(self, domain):
            for rec in self.recordList.values():
                if rec.getDomain() == domain:
                    rec.checkWayback()

        def updateDomainCheck(self, id, domainCheck):
            self.recordList[id].setDomainCheck(domainCheck)

        def getReportRows(self):
            for r in self.recordList.values():
                yield r.getEmailReportRow()

        def getUniqueReportRows(self):
            uniqueList = []
            for r in self.getReportRows():
                if not r in uniqueList:
                    uniqueList.append(r)
            return uniqueList


        class EmailRecord(object):
            def __init__(self, email, tldCheck, domainCheck, domainChecked):
                self.email = email
                self.tldCheck = tldCheck
                self.domainCheck = domainCheck
                self.wb = "n.a.;"
                self.domainChecked = domainChecked

            def setDomainCheck(self, domainCheck):
                self.domainCheck = domainCheck
                self.domainChecked = True

            def getDomain(self):
                domain = self.email.split("@")
                return domain[-1].lower()

            def getEmail(self):
                return self.email

            def getTLD(self):
                return self.email.split(".")[-1]

            def getTLDCheck(self):
                return self.tldCheck

            def getAlphaCheck(self):
                return not re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', self.email.lower()) == None

            def checkAlpha(self):
                self.alphaCheck = self.getAlphaCheck()

            def checkTLD(self, tldList):
                self.tldCheck = False
                tld = self.email.split(".")
                if tld[-1].upper() in tldList:
                    self.tldCheck = True

            def checkWayback(self):
                
                # url for Wayback machine
                urlWayback = 'http://archive.org/wayback/available'

                if self.domainCheck == False:

                    response = urllib2.urlopen(urlWayback + "?url=" + self.getDomain())

                    wayback_json = json.load(response)
                    if wayback_json['archived_snapshots']:
                        closest = wayback_json['archived_snapshots']['closest']
                        archive_timestamp = closest.get('timestamp', None)
                        archive_url = closest.get('url', 'n.a.')
                        #return (archive_timestamp, archive_url)
                        self.wb = archive_timestamp + ";" + archive_url
                    else:
                        self.wb = "NoRecord"

            def getEmailReportRow(self):
                alphaCheckRes = "0"
                tldRes = "0"
                domainRes = "0"
                domainCheckedStatus = "0"
                if self.alphaCheck:
                    alphaCheckRes = "1"
                if self.tldCheck:
                    tldRes = "1"
                if self.domainCheck:
                    domainRes = "1"
                if self.domainChecked:
                    domainCheckedStatus = "1"
                return self.email + ";" + alphaCheckRes + ";" + self.getTLD() + ";"  + tldRes + ";" + self.getDomain() + ";" + domainCheckedStatus + ";" + domainRes + ";" + self.wb

