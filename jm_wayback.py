# *************************************************************************
# * Class (Task): check if domain is valid by performing DNS Lookup on it *
# *************************************************************************
import os
import urllib2
import java.net.InetAddress
import java.net.UnknownHostException
import random
import json

from time import sleep

from threading import Thread


class WaybackTask(Thread):
    def __init__ (self, qu_in, qu_out_valid, qu_out_invalid):
        Thread.__init__(self)
        self.qu_in = qu_in
        self.qu_out_valid = qu_out_valid
        self.qu_out_invalid = qu_out_invalid
    def run(self):
        # wait for 0-2 seconds before starting task
        sleep(random.uniform(0,2))
        while (not self.qu_in.empty()):
            url = self.qu_in.get(block = True, timeout = 5)
            # url for Wayback machine
            urlWayback = 'http://archive.org/wayback/available'

            response = urllib2.urlopen(urlWayback + "?url=" + self.getDomain())

            wayback_json = json.load(response)
            if wayback_json['archived_snapshots']:
                closest = wayback_json['archived_snapshots']['closest']
                archive_timestamp = closest.get('timestamp', None)
                archive_url = closest.get('url', 'n.a.')
                res = archive_timestamp + " - " + archive_url
                self.qu_out_valid.put(url,res)
            else:
                self.qu_out_invalid.put(url)
