# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_email
# Purpose:      SpiderFoot plug-in for scanning retrieved content by other
#               modules (such as sfp_spider) and identifying e-mail addresses
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     MIT
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin

# Cloudflare obfuscates addresses as <a data-cfemail="HEX">; the plaintext is the
# hex XOR'd with the first byte. Regex extraction alone misses these entirely.
_CFEMAIL_RE = re.compile(r'data-cfemail="([0-9a-fA-F]{6,})"')


def _decode_cfemail(hexstr: str) -> str:
    try:
        key = int(hexstr[:2], 16)
        return "".join(chr(int(hexstr[i:i + 2], 16) ^ key)
                       for i in range(2, len(hexstr), 2))
    except Exception:
        return ""


class sfp_email(SpiderFootPlugin):

    meta = {
        'name': "E-Mail Address Extractor",
        'summary': "Identify e-mail addresses in any obtained data.",
        'useCases': ["Passive", "Investigate", "Footprint"],
        'categories': ["Content Analysis"]
    }

    opts = {
    }

    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT", "BASE64_DATA", "AFFILIATE_DOMAIN_WHOIS",
                "CO_HOSTED_SITE_DOMAIN_WHOIS", "DOMAIN_WHOIS", "NETBLOCK_WHOIS",
                "LEAKSITE_CONTENT", "RAW_DNS_RECORDS", "RAW_FILE_META_DATA",
                'RAW_RIR_DATA', "SIMILARDOMAIN_WHOIS",
                "SSL_CERTIFICATE_RAW", "SSL_CERTIFICATE_ISSUED", "TCP_PORT_OPEN_BANNER",
                "WEBSERVER_BANNER", "WEBSERVER_HTTPHEADERS"]

    # What events this module produces
    def producedEvents(self):
        return ["EMAILADDR", "EMAILADDR_GENERIC", "AFFILIATE_EMAILADDR"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        emails = set(SpiderFootHelpers.extractEmailsFromText(eventData))
        # Also recover Cloudflare-obfuscated addresses from raw page content.
        for hexstr in _CFEMAIL_RE.findall(eventData):
            decoded = _decode_cfemail(hexstr)
            if "@" in decoded and "." in decoded.split("@")[-1]:
                emails.add(decoded)
        for email in emails:
            evttype = "EMAILADDR"
            email = email.lower()

            # Get the domain and strip potential ending .
            mailDom = email.split('@')[1].strip('.')
            if not self.sf.validHost(mailDom, self.opts['_internettlds']):
                self.debug(f"Skipping {email} as not a valid e-mail.")
                continue

            if not self.getTarget().matches(mailDom, includeChildren=True, includeParents=True) and not self.getTarget().matches(email):
                self.debug("External domain, so possible affiliate e-mail")
                evttype = "AFFILIATE_EMAILADDR"

            if eventName.startswith("AFFILIATE_"):
                evttype = "AFFILIATE_EMAILADDR"

            if not evttype.startswith("AFFILIATE_") and email.split("@")[0] in self.opts['_genericusers'].split(","):
                evttype = "EMAILADDR_GENERIC"

            self.info(f"Found e-mail address: {email}")
            mail = email.strip('.')

            evt = SpiderFootEvent(evttype, mail, self.__name__, event)
            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"
            self.notifyListeners(evt)

# End of sfp_email class
