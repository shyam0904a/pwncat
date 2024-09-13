#!/usr/bin/env python3
import json
from typing import List, Optional
from importlib import resources

from pwncat.db import Fact
from pwncat.facts import ArchData, HostnameData
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule

# ... [KernelVersionData and KernelVulnerabilityData classes remain unchanged] ...

class Module(EnumerateModule):
    """
    Enumerate standard system properties provided by the
    `uname` command. This will enumerate the kernel name,
    version, hostname (nodename), machine hardware name,
    and operating system name (normally GNU/Linux).

    This module also provides a similar enumeration to the
    common Linux Exploit Suggester, and will report known
    vulnerabilities which are applicable to the detected
    kernel version.
    """

    PROVIDES = [
        "system.kernel.version",
        "system.hostname",
        "system.arch",
        "system.kernel.vuln",
    ]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session):
        """Run uname and organize information"""

        # Grab the uname output
        output = session.platform.run(
            "uname -s -n -r -m -o", capture_output=True, text=True, check=True
        )

        fields = output.stdout.split(" ")

        # Grab the components
        # kernel_name = fields[0] if len(fields) > 0 else None
        hostname = fields[1] if len(fields) > 1 else None
        kernel_revision = fields[2] if len(fields) > 2 else None
        machine_name = fields[3] if len(fields) > 3 else None
        # operating_system = fields[4] if len(fields) > 4 else None

        if kernel_revision:
            # Handle kernel versions
            w, x, *y_and_z = kernel_revision.split(".")
            y_and_z = ".".join(y_and_z).split("-")
            y = y_and_z[0]
            z = "-".join(y_and_z[1:]) if len(y_and_z) > 1 else ""
            version = KernelVersionData(self.name, int(w), int(x), int(y), z)
            yield version

            # Handle Kernel vulnerabilities
            lester_json = resources.read_text("pwncat.data", "lester.json")
            vulns = json.loads(lester_json)

            version_string = f"{version.major}.{version.minor}.{version.patch}"
            for name, vuln in vulns.items():
                if version_string not in vuln["vuln"]:
                    continue
                yield KernelVulnerabilityData(
                    self.name,
                    name,
                    vuln["vuln"],
                    vuln.get("mil", None),
                    vuln.get("cve", None),
                )

        # Handle arch
        yield ArchData(self.name, machine_name)

        # Handle Hostname
        yield HostnameData(self.name, hostname)