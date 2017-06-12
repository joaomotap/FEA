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
# See http://sleuthkit.org/autopsy/docs/api-docs/3.1/index.html for documentation

import os
import inspect
import urllib2
import json
import datetime
import xlwt
import ecdsa
import ecdsa.der
import ecdsa.util
import hashlib
import re
import struct
#import dns.resolver

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

from hashlib import sha256


class BCHitsReportModule(GeneralReportModuleAdapter):

    moduleName = "FEA - BC Wallet Validation"

    _logger = None

    def log(self, level, msg):
        if self._logger == None:
            self._logger = Logger.getLogger(self.moduleName)
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "BC Wallet Hit Reports"

    def getRelativeFilePath(self):
        return "FEA-BC-JM.txt"

    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, baseReportDir, progressBar):

        self.log(Level.INFO, "*****************************************************")
        self.log(Level.INFO, "* [JM] Scraping artifacts from blackboard starting  *")
        self.log(Level.INFO, "*****************************************************")

        # configure excel report
        fileNameExcel = os.path.join(baseReportDir, Case.getCurrentCase().getName() + "_BC_FEA.xls")
        book = xlwt.Workbook(encoding="utf-8")
        sheetPublicAddresses = book.add_sheet("FEA_BC_Public_wallets")
        sheetPrivateAddresses = book.add_sheet("FEA_BC_Private_wallets")
        styleRowHeaders = xlwt.easyxf('font: name Arial, color-index blue, bold on', num_format_str='#,##0.00')
        sheetPublicAddresses.write(0,0,"Address", styleRowHeaders)
        sheetPublicAddresses.write(0,1,"Time 1st seen", styleRowHeaders)
        sheetPublicAddresses.write(0,2,"Balance", styleRowHeaders)
        sheetPublicAddresses.write(0,3,"Total Received", styleRowHeaders)
        sheetPublicAddresses.write(0,4,"Blockchain.info", styleRowHeaders)
        sheetPrivateAddresses.write(0,0,"Address", styleRowHeaders)
        sheetPrivateAddresses.write(0,1,"Public wallet", styleRowHeaders)
        sheetPrivateAddresses.write(0,2,"Balance", styleRowHeaders)

        # configure progress bar
        progressBar.setIndeterminate(False)
        progressBar.start()

        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()

        # TODO: the name of the hash list should be retrieved from the GUI settings dialog
        bcArtifacts = sleuthkitCase.getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, "testlist")
        progressTotal = len(bcArtifacts)

        progressBar.setMaximumProgress(progressTotal + 1)

        #inits
        artifactCount = 0
        recordDB = self.BlockchainReport()

        # Get Blackboard artifacts
        # Emails:
        # display name: E-Mail Messages; ID: 13; type name: TSK_EMAIL_MSG
        # display name: Accounts; ID: 21; type name: TSK_SERVICE_ACCOUNT
        # display name: Accounts; ID: 39; type name: TSK_ACCOUNT
        # atributo para sets de keywords: TSK_SET_NAME

        # Write the results to the report file.
        fileName = os.path.join(baseReportDir, self.getRelativeFilePath())
        report = open(fileName, 'w')
        report.write("Attributes from artifacts\n")

        for artifactItem in bcArtifacts:
            for attributeItem in artifactItem.getAttributes(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD):
                bcAddress = attributeItem.getDisplayString()
                self.log(Level.INFO, "[JM] Bitcoin Address: " + bcAddress)

                if not self.check_bc(bcAddress):
                    self.log(Level.INFO, "[JM] Bitcoin address is not valid")
                    #report.write("%s - not valid;\n" % bcAddress)
                else:
                    self.log(Level.INFO, "[JM] Bitcoin address is valid")
                    if len(bcAddress) < 51:
                        balance, received, timeFirstSeen = self.checkBlockchain(bcAddress)
                        recordDB.addBlockchainRecord(bcAddress, 0, timeFirstSeen, balance, received)
                        report.write("%s - first seen on: %s - account balance:  %s BTC - total received: %s BTC;\n" % (bcAddress, timeFirstSeen, balance, received))
                    else:
                        self.log(Level.INFO, "[JM] Candidate private key found !!!")
                        if bcAddress[0] == '5':
                            self.log(Level.INFO, "[JM] TODO: check uncompressed private keys!")
                            #candidatePublicAddress = self.keyToAddr(bcAddress)
                            #if self.check_bc(candidatePublicAddress):
                            #    balance, received, timeFirstSeen = self.checkBlockchain(bcAddress)
                            #    self.log(Level.INFO, "[JM] Matching wallet! balance: " + balance + "; time1stSeen: " + time1stSeen)
                        else:
                            self.log(Level.INFO, "[JM] TODO: check compressed private keys!")

            artifactCount += 1
            progressBar.increment()

        report.write("Artifacts processed = %d" % artifactCount)
        report.close()

        # write excel report
        baseCellPublic = 1
        baseCellPrivate = 1
        for row in recordDB.getAllRecords():
            # write public wallet addresses in subsheet
            if row.getAddressType() == 0:
                sheetPublicAddresses.write(baseCellPublic, 0, row.getAddress())
                sheetPublicAddresses.write(baseCellPublic, 1, row.getTimeFirstSeen())
                sheetPublicAddresses.write(baseCellPublic, 2, row.getAccountBalance())
                sheetPublicAddresses.write(baseCellPublic, 3, row.getTotalReceived())
                sheetPublicAddresses.write(baseCellPublic, 4, "https://blockchain.info/address/" + row.getAddress())
                baseCellPublic += 1
        book.save(fileNameExcel)
        Case.getCurrentCase().addReport(fileNameExcel, self.moduleName, "FEA Blockchain address analysis report (eXcel)")

        # Add the report to the Case, so it is shown in the tree
        Case.getCurrentCase().addReport(fileName, self.moduleName, "Artifact Keyword Count Report");

        # last step (file write) complete
        progressBar.increment()

        # Call this with ERROR if report was not generated
        progressBar.complete(ReportStatus.COMPLETE)




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
        # TODO: implementar lógica no painel e tratar eventos
        panel0 = JPanel(GridBagLayout())

        gbc = GridBagConstraints()
        gbc.anchor = GridBagConstraints.NORTH
        gbc.gridx = 0
        gbc.gridy = 0


        cbNSLookup = JCheckBox("Find bitcoin addresses")
        panel0.add(cbNSLookup, gbc)

        gbc.gridy = 1
        cbHitlist = JTextField("Base list of hashes to analyze")
        panel0.add(cbHitlist, gbc)

        cbBlockchainCheck = JCheckBox("Query Blockchain.info")
        panel0.add(cbBlockchainCheck, gbc)

        return panel0



#   /$$$$$$$  /$$   /$$                         /$$                                 /$$       /$$                                       
#  | $$__  $$|__/  | $$                        |__/                                | $$      | $$                                       
#  | $$  \ $$ /$$ /$$$$$$    /$$$$$$$  /$$$$$$  /$$ /$$$$$$$         /$$$$$$   /$$$$$$$  /$$$$$$$  /$$$$$$   /$$$$$$   /$$$$$$$ /$$$$$$$
#  | $$$$$$$ | $$|_  $$_/   /$$_____/ /$$__  $$| $$| $$__  $$       |____  $$ /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$ /$$_____//$$_____/
#  | $$__  $$| $$  | $$    | $$      | $$  \ $$| $$| $$  \ $$        /$$$$$$$| $$  | $$| $$  | $$| $$  \__/| $$$$$$$$|  $$$$$$|  $$$$$$ 
#  | $$  \ $$| $$  | $$ /$$| $$      | $$  | $$| $$| $$  | $$       /$$__  $$| $$  | $$| $$  | $$| $$      | $$_____/ \____  $$\____  $$
#  | $$$$$$$/| $$  |  $$$$/|  $$$$$$$|  $$$$$$/| $$| $$  | $$      |  $$$$$$$|  $$$$$$$|  $$$$$$$| $$      |  $$$$$$$ /$$$$$$$//$$$$$$$/
#  |_______/ |__/   \___/   \_______/ \______/ |__/|__/  |__/       \_______/ \_______/ \_______/|__/       \_______/|_______/|_______/ 
#                                                                                                                                       
#                                                                                                                                       
#             

    # TODO: consider "deep" validation: https://bitcointalk.org/index.php?topic=1026.0

    def to_bytes(self, n, length, endianess='big'):
        h = '%x' % n
        s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
        return s if endianess == 'big' else s[::-1]

    def check_bc(self, bc):
        digits58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

        n = 0
        for char in bc:
            n = n * 58 + digits58.index(char)
        bcbytes = self.to_bytes(n, 25, 'big')

        return bcbytes[-4:] == sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]

    def checkBlockchain(self, walletAddress):
        
        # url for Blockchain API - simple queries
        urlBlockchain = 'https://blockchain.info'
        # minimum number of confirmations to consider info valid
        numConfirmations = 6

        # TODO: check for exceptions!
        #self.log(Level.INFO, "Blockchain query: " + urlBlockchain + "/q/addressbalance/" + walletAddress + "?confirmations=" + str(numConfirmations))
        response = urllib2.urlopen(urlBlockchain + "/q/addressbalance/" + walletAddress + "?confirmations=" + str(numConfirmations))
        balance = json.load(response) / 100000000

        response = urllib2.urlopen(urlBlockchain + "/q/getreceivedbyaddress/" + walletAddress + "?confirmations=" + str(numConfirmations))
        received = json.load(response) / 100000000

        response = urllib2.urlopen(urlBlockchain + "/q/addressfirstseen/" + walletAddress)
        timeFirstSeen = json.load(response)
        if (timeFirstSeen != 0):
            reg = datetime.datetime.fromtimestamp(int(timeFirstSeen)).strftime('%Y-%m-%d %H:%M:%S')
        else:
            reg = "n.a."

        return str(balance), str(received), reg

    def keyToAddr(self, s):
        t='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

        fromWif = str(sum([t.index(s[::-1][l])*(58**l) for l in range(len(s))])/(2**32)%(2**256))
        sk = ecdsa.SigningKey.from_string(fromWif.decode('hex'), curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        sEnc=('\04' + sk.verifying_key.to_string()).encode('hex')
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(sEnc.decode('hex')).digest())
        return base58CheckEncode(0, ripemd160.digest())


#   /$$$$$$$                                            /$$                     /$$                                                 
#  | $$__  $$                                          | $$                    | $$                                                 
#  | $$  \ $$  /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$  /$$$$$$          /$$$$$$$| $$  /$$$$$$   /$$$$$$$ /$$$$$$$  /$$$$$$   /$$$$$$$
#  | $$$$$$$/ /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$|_  $$_/         /$$_____/| $$ |____  $$ /$$_____//$$_____/ /$$__  $$ /$$_____/
#  | $$__  $$| $$$$$$$$| $$  \ $$| $$  \ $$| $$  \__/  | $$          | $$      | $$  /$$$$$$$|  $$$$$$|  $$$$$$ | $$$$$$$$|  $$$$$$ 
#  | $$  \ $$| $$_____/| $$  | $$| $$  | $$| $$        | $$ /$$      | $$      | $$ /$$__  $$ \____  $$\____  $$| $$_____/ \____  $$
#  | $$  | $$|  $$$$$$$| $$$$$$$/|  $$$$$$/| $$        |  $$$$/      |  $$$$$$$| $$|  $$$$$$$ /$$$$$$$//$$$$$$$/|  $$$$$$$ /$$$$$$$/
#  |__/  |__/ \_______/| $$____/  \______/ |__/         \___/         \_______/|__/ \_______/|_______/|_______/  \_______/|_______/ 
#                      | $$                                                                                                         
#                      | $$                                                                                                         
#                      |__/                                                                                                         


    class BlockchainReport(object):
        def __init__(self):
            self.recordList = {}
            self.recordCount = 0

        def addBlockchainRecord(self, walletAddress, walletType, timeFirstSeen, totalBalance, totalReceived):
            self.recordCount += 1
            newRecord = self.BlockchainRecord(walletAddress, walletType, timeFirstSeen, totalBalance, totalReceived)
            self.recordList[walletAddress] = newRecord
        
        def getAllRecords(self):
            return self.recordList.values()

        class BlockchainRecord(object):
            def __init__(self, walletAddress, walletType, timeFirstSeen, totalBalance, totalReceived):
                self.walletAddress = walletAddress
                self.walletType = walletType
                self.timeFirstSeen = timeFirstSeen
                self.totalBalance = totalBalance
                self.totalReceived = totalReceived

            def getAddressType(self):
                return self.walletType

            def getAddress(self):
                return self.walletAddress

            def getTimeFirstSeen(self):
                return self.timeFirstSeen

            def getAccountBalance(self):
                return self.totalBalance

            def getTotalReceived(self):
                return self.totalReceived