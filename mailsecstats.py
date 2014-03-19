#!/usr/bin/env python
import sys, os, re
import mailbox

# Transmissions are estimated to be secure if (1) they're encrypted or (2) they're localhost transfers

IPREGEXP="\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
secREs = [
  re.compile("(with e?smtpsa?[;\s]|with asmtp[;\s]|[^a-z](TLS|SSL|SMTPSVC)v?[^a-z]|Microsoft SMTPSVC|encrypted smtp|encrypted\))", re.IGNORECASE),
  re.compile(" with (local|queue id|LMTP|spool\s|QMTP|qmail-scanner|sa-checked)"),
  re.compile(" from (/spool/local|localhost|127.0.0.1|::1)"),
  re.compile(" from [a-zA-Z0-9\.\-]+ (\(\[/spool/local|localhost|127.0.0.1|::1\]\))"),
  re.compile(" from [a-zA-Z0-9\.\-]+ (\(\["+IPREGEXP+"\]\)) by [a-zA-Z0-9\.\-]+ \\1")  # any IP to itself
]

# These look like unencrypted network transfers
insecREs = [
  re.compile("with e?smtpa?(m*)[;\s]", re.IGNORECASE),
  re.compile("with (Microsoft SMTP Server|bizsmtp|asmtp|\[InBox.Com SMTP Server\]|UUCP|TCP|MS-Webstorage|emfmta|IBM ESMTP SMTP|Novell_GroupWise)")
]
# We generally can't tell if webmail interfaces were HTTPS
httpRE = re.compile("with (HTTP|webmail|Microsoft Exchange.*HTTP-DAV|Safe-mail)", re.IGNORECASE)
mapiRE = re.compile("with MAPI", re.IGNORECASE)
spamRE = re.compile("with spam-scanned ", re.IGNORECASE)
nnfmpRE = re.compile("with NNFMP[ ;]", re.IGNORECASE)

# These things are, not sure if they're secure or not...
weirdRE = re.compile("with (PIPE|ECSTREAM|M\+ Extreme|QMQP|Exchange Front|ME|Mail2World|MailEnable)", re.IGNORECASE)

standaloneSpamScanRE = re.compile("with (NO UCE|with InterScan Message)", re.IGNORECASE)  # these go over LANs/WANs... unclear how safe they are

comcastRE = re.compile("with comcast", re.IGNORECASE)

miscREs = [httpRE, spamRE, weirdRE, mapiRE, nnfmpRE, comcastRE, standaloneSpamScanRE]


def extractHeadersMaildir(msg, hdr):
  # Add a base case for reduction
  rawHeaderLines = [[]] + msg.getallmatchingheaders(hdr)
  return reduce(mergeContinuedHeaders, rawHeaderLines)

def extractHeadersMbox(msg,hdr):
  return msg.get_all(hdr)
 
def mergeContinuedHeaders(prevheaders, newline):
  # the API at http://docs.python.org/2/library/rfc822.html?highlight=getallmatchingheaders#rfc822.Message.getallmatchingheaders
  # is totally messed up for headers with continuations, so we have to dig ourselves out....
  nl = newline.strip() # undoing wrapping & indentation
  
  if nl.startswith("Received:"):
    # New header, make a new list entry
    prevheaders.append(nl)
  else:
    # Continuation line, stick it onto the last header in the list
    last = prevheaders.pop()
    prevheaders.append(last + " " + nl)
  return prevheaders
  #print "======================================="


def main():
  mailboxes = sys.argv[1:]
  if not mailboxes:
    sys.stderr.write("Usage: %s <mailbox> [mailbox] ..\n" % sys.argv[0])
    sys.stderr.write("\n  mailboxes can be Maildir or mbox\n")
    sys.exit(1)
  counter = SecureMessageCounter()
  for m in mailboxes:
    if os.path.isdir(m):
      box = mailbox.Maildir(m)
      extractor = extractHeadersMaildir
      counter.countMessages(box, extractHeadersMaildir)
    elif os.path.isfile(m):
      box = mailbox.mbox(m)
      counter.countMessages(box, extractHeadersMbox)
    else:
      sys.stderr.write("Invalid mailbox %s\n" % m)
  counter.report()

class SecureMessageCounter:

  def __init__(self):
    self.secure = 0
    self.insecure = 0
    self.mixed = 0
    self.unknown = 0
    self.wtf = 0

  def countMessages(self, box, extractor):
    for key in box.iterkeys():
      msg=box[key]
      smtp = 0
      smtps = 0
      hdrs = extractor(msg, "received")
      for hdr in hdrs:
        if any([r.search(hdr) for r in secREs]):
          smtps += 1
        elif any([r.search(hdr) for r in insecREs]):
          smtp += 1
        else:
          if not any([r.search(hdr) for r in miscREs]):
            if " with " in hdr:
              self.wtf +=1
              print "DO NOT UNDERSTAND"
              print hdr
      if smtps and smtp: 
        self.mixed +=1
      elif smtps: 
        self.secure +=1
      elif smtp: 
        self.insecure +=1
      else:
        self.unknown +=1
        #print "NO KNOWN HEADERS IN"
        #print msg.get_all("received")

  def report(self):
    print "SECURE", self.secure
    print "INSECURE", self.insecure
    print "MIXED", self.mixed
    print "UNKNOWN", self.unknown
    print "WTF headers", self.wtf

if __name__ == "__main__":
  main()
