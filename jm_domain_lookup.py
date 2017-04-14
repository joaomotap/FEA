# *************************************************************************
# * Class (Task): check if domain is valid by performing DNS Lookup on it *
# *************************************************************************
import os
import urllib2
import java.net.InetAddress
import java.net.UnknownHostException
import random

from time import sleep

from threading import Thread


class DomainLookupTask(Thread):
    def __init__ (self, qu_in, qu_out_valid, qu_out_invalid):
        Thread.__init__(self)
        self.qu_in = qu_in
        self.qu_out_valid = qu_out_valid
        self.qu_out_invalid = qu_out_invalid
    def run(self):
        sleep(random.uniform(0,2))
        while (not self.qu_in.empty()):
            url = self.qu_in.get(block = True, timeout = 5)
            try:
                inetHost = java.net.InetAddress.getByName(url)
                hostName = inetHost.getHostName()
                self.qu_out_valid.put(url)
            except java.net.UnknownHostException as e:
                self.qu_out_invalid.put(url)