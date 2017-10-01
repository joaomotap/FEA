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


# Bitcoin/blockchain addresses analysis report module for Autopsy.
#
# by João Mota

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
import binascii
import re
import struct
import time

from javax.swing import JPanel
from javax.swing import JCheckBox
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JLabel
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints

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
        return "Reports on Bitcoin wallets/private keys (note: requires appropriate RegExes to be setup as specified in the documentation)"

    def getRelativeFilePath(self):
        return "FEA-BitCoin.txt"

    def generateReport(self, baseReportDir, progressBar):

        # retrieve configuration settings
        blockchainCheck = self.configPanel.getBlockchainCheck()
        configList = self.configPanel.getHitlist()
        timeoutBlockchain = self.configPanel.getMaxTimeout()

        # configure excel report
        fileNameExcel = os.path.join(baseReportDir, Case.getCurrentCase().getName() + "_BitCoin_FEA.xls")
        book = xlwt.Workbook(encoding="utf-8")
        sheetPublicAddresses = book.add_sheet("FEA_BC_Public_wallets")
        sheetPrivateAddresses = book.add_sheet("FEA_BC_Private_wallets")
        styleRowHeaders = xlwt.easyxf('font: name Arial, color-index blue, bold on', num_format_str='#,##0.00')
        sheetPublicAddresses.write(0,0,"Address", styleRowHeaders)
        sheetPublicAddresses.write(0,1,"Time 1st seen", styleRowHeaders)
        sheetPublicAddresses.write(0,2,"Balance", styleRowHeaders)
        sheetPublicAddresses.write(0,3,"Total Received", styleRowHeaders)
        sheetPublicAddresses.write(0,4,"Blockchain.info", styleRowHeaders)
        sheetPrivateAddresses.write(0,0,"Private Key", styleRowHeaders)
        sheetPrivateAddresses.write(0,1,"Wallet Address", styleRowHeaders)
        sheetPrivateAddresses.write(0,2,"Balance", styleRowHeaders)
        sheetPrivateAddresses.write(0,3,"Time 1st seen", styleRowHeaders)
        sheetPrivateAddresses.write(0,4,"Total received", styleRowHeaders)

        # configure progress bar
        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.updateStatusLabel("Initializing")

        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()

        bcArtifacts = sleuthkitCase.getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, configList)
        progressTotal = len(bcArtifacts)

        progressBar.setMaximumProgress(progressTotal + 1)

        #misc inits
        artifactCount = 0
        recordDB = self.BlockchainReport()
        skipFirstTimeout = True

        # Write the results to the report file.
        fileName = os.path.join(baseReportDir, self.getRelativeFilePath())
        report = open(fileName, 'w')
        report.write("Attributes from artifacts\n")

        for artifactItem in bcArtifacts:
            for attributeItem in artifactItem.getAttributes(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD):
                bcAddress = attributeItem.getDisplayString()
                
                # Delay for accessing Blockchain.info not used on first iteration
                if skipFirstTimeout:
                    skipFirstTimeout = False
                else:
                    progressBar.updateStatusLabel("Waiting for %s secs before checking address %s with the Blockchain API" % (timeoutBlockchain, bcAddress))
                    time.sleep(timeoutBlockchain)
                
                progressBar.updateStatusLabel("Analyzing hash: " + bcAddress)

                if self.check_bc(bcAddress):
                    if len(bcAddress) < 51:
                        if blockchainCheck:
                            balance, received, timeFirstSeen = self.checkBlockchain(bcAddress)
                            recordDB.addBlockchainRecord(bcAddress, 0, timeFirstSeen, balance, received)
                            report.write("Wallet address: %s - first seen on: %s - account balance:  %s BTC - total received: %s BTC;\n" % (bcAddress, timeFirstSeen, balance, received))
                        else:
                            recordDB.addBlockchainRecord(bcAddress, 0, 0, 0, 0)
                            report.write("Wallet address: %s (user opted out of Blockchain check)\n" % bcAddress)
                    else:
                        # candidate private key found
                        candidatePublicAddress = self.getAddressFromPrivateKey(bcAddress)
                        # candidate wallet address found
                        if self.check_bc(candidatePublicAddress):
                            balance, received, timeFirstSeen = self.checkBlockchain(candidatePublicAddress)
                            recordDB.addPrivateWallet(candidatePublicAddress, timeFirstSeen, balance, received, bcAddress)
                            report.write("*** PRIVATE KEY FOUND: %s with wallet address: %s - first seen on: %s - account balance:  %s BTC - total received: %s BTC;\n" % (bcAddress, candidatePublicAddress, timeFirstSeen, balance, received))

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
                if blockchainCheck:
                    sheetPublicAddresses.write(baseCellPublic, 1, row.getTimeFirstSeen())
                    sheetPublicAddresses.write(baseCellPublic, 2, row.getAccountBalance())
                    sheetPublicAddresses.write(baseCellPublic, 3, row.getTotalReceived())
                    sheetPublicAddresses.write(baseCellPublic, 4, "https://blockchain.info/address/" + row.getAddress())
                else:
                    for n in range(1, 4):
                        sheetPublicAddresses.write(baseCellPublic, n, "n.a")
                    sheetPublicAddresses.write(baseCellPublic, 4, "user opted out of blockchain.info check")
                baseCellPublic += 1

        for row in recordDB.getAllPrivateKeyRecords():
            # write private key addresses in subsheet
            sheetPrivateAddresses.write(baseCellPrivate, 0, row.getPrivateKey())
            sheetPrivateAddresses.write(baseCellPrivate, 1, row.getAddress())
            sheetPrivateAddresses.write(baseCellPrivate, 2, row.getAccountBalance())
            sheetPrivateAddresses.write(baseCellPrivate, 3, row.getTimeFirstSeen())
            sheetPrivateAddresses.write(baseCellPrivate, 4, row.getTotalReceived())
            baseCellPrivate += 1

        book.save(fileNameExcel)
        Case.getCurrentCase().addReport(fileNameExcel, self.moduleName, "FEA Blockchain address analysis report (eXcel)")

        # Add the report to the Case, so it is shown in the tree
        Case.getCurrentCase().addReport(fileName, self.moduleName, "Artifact Keyword Count Report");

        # last step (file write) complete
        progressBar.increment()

        # Call this with ERROR if report was not generated
        progressBar.complete(ReportStatus.COMPLETE)



    # *******************************************
    # * Function: implement config settings GUI *
    # *******************************************
    def getConfigurationPanel(self):

        self.configPanel = FEA_BC_ConfigPanel()
        return self.configPanel



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
        # minimum number of confirmations to consider information retrieved as valid
        numConfirmations = 6

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

    def getAddressFromPrivateKey(self, wifpriv):
        # generate public wallet address for private key from via elliptic curve algorithn
        t='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        pk = sum([t.index(wifpriv[::-1][l])*(58**l) for l in range(len(wifpriv))])/(2**32)%(2**256)

        secp256k1curve=ecdsa.ellipticcurve.CurveFp(115792089237316195423570985008687907853269984665640564039457584007908834671663,0,7)
        secp256k1point=ecdsa.ellipticcurve.Point(secp256k1curve,0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
        secp256k1=ecdsa.curves.Curve('secp256k1',secp256k1curve,secp256k1point,(1,3,132,0,10))

        pko=ecdsa.SigningKey.from_secret_exponent(pk,secp256k1)
        pubkey=binascii.hexlify(pko.get_verifying_key().to_string())
        pubkey2=hashlib.sha256(binascii.unhexlify('04'+pubkey)).hexdigest()
        pubkey3=hashlib.new('ripemd160',binascii.unhexlify(pubkey2)).hexdigest()
        pubkey4=hashlib.sha256(binascii.unhexlify('00'+pubkey3)).hexdigest()
        pubkey5=hashlib.sha256(binascii.unhexlify(pubkey4)).hexdigest()
        pubkey6=pubkey3+pubkey5[:8]
        pubnum=int(pubkey6,16)
        pubnumlist=[]
        while pubnum!=0: pubnumlist.append(pubnum%58); pubnum/=58
        address=''
        for l in ['123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[x] for x in pubnumlist]:
            address=l+address
        return '1'+address


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
            self.privateKeysList = {}
            self.privateKeysCount = 0

        def addBlockchainRecord(self, walletAddress, walletType, timeFirstSeen, totalBalance, totalReceived):
            self.recordCount += 1
            newRecord = self.BlockchainRecord(walletAddress, walletType, timeFirstSeen, totalBalance, totalReceived)
            self.recordList[walletAddress] = newRecord

        def addPrivateWallet(self, walletAddress, timeFirstSeen, totalBalance, totalReceived, privateKey):
            self.privateKeysCount += 1
            newRecord = self.BlockchainRecord(walletAddress, 1, timeFirstSeen, totalBalance, totalReceived, privateKey)
            self.privateKeysList[privateKey] = newRecord
        
        def getAllRecords(self):
            return self.recordList.values()

        def getAllPrivateKeyRecords(self):
            return self.privateKeysList.values()

        class BlockchainRecord(object):
            def __init__(self, walletAddress, walletType, timeFirstSeen, totalBalance, totalReceived, privateKey=None):
                self.walletAddress = walletAddress
                self.walletType = walletType
                self.timeFirstSeen = timeFirstSeen
                self.totalBalance = totalBalance
                self.totalReceived = totalReceived
                self.privateKey = privateKey

            def getPrivateKey(self):
                return self.privateKey

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

class FEA_BC_ConfigPanel(JPanel):
    
    cbBlockchainCheck = None
    tbHitlist = None
    blockchainCheck = True
    hitlist = "testlist"
    maxTimeout = 5
    tbMaxBCHits = None
    
    def __init__(self):

        self.initComponents()
        
        #get previous settings selected by the user

        if (ModuleSettings.getConfigSetting("FEA", "hitlist") != None) and (ModuleSettings.getConfigSetting("FEA","hitlist") != ""):
            if ModuleSettings.getConfigSetting("FEA","hitlist"):
                self.tbHitlist.text = ModuleSettings.getConfigSetting("FEA", "hitlist")
            else:
                self.tbHitlist.text = "testlist"

        if (ModuleSettings.getConfigSetting("FEA", "maxTimeout") != None) and (ModuleSettings.getConfigSetting("FEA","maxTimeout") != ""):
            if ModuleSettings.getConfigSetting("FEA","maxTimeout"):
                self.tbMaxBCHits.text = ModuleSettings.getConfigSetting("FEA", "maxTimeout")
            else:
                self.tbMaxBCHits.text = "5"

        if (ModuleSettings.getConfigSetting("FEA", "blockchainCheck") != None) and (ModuleSettings.getConfigSetting("FEA","blockchainCheck") != ""):
            if ModuleSettings.getConfigSetting("FEA","blockchainCheck"):
                self.cbBlockchainCheck.setSelected(True)
                self.blockchainCheck = True
            else:
                self.cbBlockchainCheck.setSelected(False)
                self.blockchainCheck = False

    def addStatusLabel(self, msg):
            gbc = GridBagConstraints()
            gbc.anchor = GridBagConstraints.NORTHWEST
            gbc.gridx = 0
            gbc.gridy = 7
            lab = JLabel(msg)
            self.add(lab, gbc)

    def getHitlist(self):
        return self.hitlist

    def getBlockchainCheck(self):
        return self.blockchainCheck

    def getMaxTimeout(self):
        return self.maxTimeout

    def initComponents(self):

        self.setLayout(GridBagLayout())

        gbc = GridBagConstraints()
        gbc.anchor = GridBagConstraints.NORTHWEST
        gbc.gridx = 0
        gbc.gridy = 0

        descriptionLabel = JLabel("FEA - BitCoin Validation module")
        self.add(descriptionLabel, gbc)

        tlHitlist = JLabel("Base list of hashes to analyze: ")
        gbc.gridy = 1
        self.add(tlHitlist, gbc)

        self.tbHitlist = JTextField("testlist", 20)
        self.tbHitlist.addActionListener(self.tbHitlistActionPerformed)
        gbc.gridx = 1
        self.add(self.tbHitlist, gbc)

        gbc.gridx = 0
        self.cbBlockchainCheck = JCheckBox("Query Blockchain.info", actionPerformed=self.cbBlockchainCheckActionPerformed)
        self.cbBlockchainCheck.setSelected(True)
        gbc.gridy = 2
        self.add(self.cbBlockchainCheck, gbc)

        tlBCMaxHits = JLabel("Timeout (in seconds) between calls to Blockchain.info: ")
        gbc.gridy = 3
        self.add(tlBCMaxHits, gbc)

        self.tbMaxBCHits = JTextField("5", 5)
        self.tbMaxBCHits.addActionListener(self.tbMaxBCHitsActionPerformed)
        gbc.gridx = 1
        self.add(self.tbMaxBCHits, gbc)
        
    def tbMaxBCHitsActionPerformed(self, event):
        source = event.getSource()
        self.maxTimeout = int(float(source.getText()))
        ModuleSettings.setConfigSetting("FEA", "maxTimeout", self.maxTimeout)

    def tbHitlistActionPerformed(self, event):
        source = event.getSource()
        self.hitlist = source.getText()
        ModuleSettings.setConfigSetting("FEA", "hitlist", self.hitlist)

    def cbBlockchainCheckActionPerformed(self, event):
        source = event.getSource()
        if(source.isSelected()):
            ModuleSettings.setConfigSetting("FEA","blockchainCheck","true")
            self.blockchainCheck = True
        else:
            ModuleSettings.setConfigSetting("FEA","blockchainCheck","false")
            self.blockchainCheck = False


