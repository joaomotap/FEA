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

# Simple file-level ingest module for Autopsy.
# Search for TODO for the things that you need to change
# See http://sleuthkit.org/autopsy/docs/api-docs/3.1/index.html for documentation

import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager

# This will work in 4.0.1 and beyond
# from org.sleuthkit.autopsy.casemodule.services import Blackboard

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.

# DONE: Rename this to something more specific.  Search and replace for it because it is used a few times
class FindBigRoundFilesIngestModuleFactory(IngestModuleFactoryAdapter):

    # DONE: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Big and Round File Finder - Tutorial by João Mota"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Finds files larger than 10Mb and with size = multiple of 4096 (Autopsy module dev tutorial - by JM)"

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return FindBigRoundFilesIngestModule()


# File-level ingest module.  One gets created per thread.
# DONE: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class FindBigRoundFilesIngestModule(FileIngestModule):

    _logger = Logger.getLogger(FindBigRoundFilesIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # DONE: Add any setup code that you need here.
    def startUp(self, context):
        self.filesFound = 0
        self.log(Level.INFO, "[JM] FindBigRoundFiles Module started")

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/4.3/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # DONE: Add your analysis code in here.
    def process(self, file):
        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
                (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
                (file.isFile() == False)):
            self.log(Level.INFO, "[JM] Non-files found")
            return IngestModule.ProcessResult.OK

        self.log(Level.INFO, "[JM] got a file to check; name=" + file.getName() + ";size=" + str(file.getSize()))
        # Look for files bigger than 10MB that are a multiple of 4096
        if ((file.getSize() > 10485760) and ((file.getSize() % 4096) == 0)):

            # Make an artifact on the blackboard.  TSK_INTERESTING_FILE_HIT is a generic type of
            # artifact.  Refer to the developer docs for other examples.
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            # add artifact to "Big and Round Files" set by defining the respective attribute
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                                      FindBigRoundFilesIngestModuleFactory.moduleName, "Big and Round Files")
            art.addAttribute(att)

            # This will work in 4.0.1 and beyond
            #try:
            #    # index the artifact for keyword search
            #    blackboard.indexArtifact(art)
            #except Blackboard.BlackboardException as e:
            #    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

            self.log(Level.INFO, "[JM] got one! firing event to UI")

            # Fire an event to notify the UI and others that there is a new artifact
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(FindBigRoundFilesIngestModuleFactory.moduleName,
                                BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

        return IngestModule.ProcessResult.OK


    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, FindBigRoundFilesIngestModuleFactory.moduleName,
            str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)