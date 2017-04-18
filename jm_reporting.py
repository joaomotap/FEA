
class EmailReport(object):

    def __init__(self):
        self.recordList = {}
        self.recordCount = 0

    def addEmailRecord(self, id, email, tldCheck=None, domainCheck=None):
        self.recordCount += 1
        newRecord = self.EmailRecord(email, tldCheck, domainCheck)
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
            return domain[-1]

        def getTLD(self):
            return self.email.split(".")[-1]

        def getEmailReportRow(self):
            tldRes = "Failed"
            domainRes = "Failed"
            if self.tldCheck:
                tldRes = "Ok"
            if self.domainCheck:
                domainRes = "Ok"
            return self.email + ";" + self.getDomain() + ";" + self.getTLD() + ";" + tldRes + ";" + domainRes
