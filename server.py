
#!/usr/bin/python

class Server():
    def __init__(self, hostname, serverid, serverlabel, servergroupname, platform, platform_version, os, kernel, machine):
        self.name = hostname
        self.id = serverid
        self.label = serverlabel
        self.group_name = servergroupname
        self.issues = ''

        #needed by Mr. Kozak
        self.platform = platform
        self.platform_version = platform_version
        self.os = os
        self.kernel = kernel
        self.machine = machine
