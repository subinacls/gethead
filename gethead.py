#!/usr/bin python

#             _   _                    _ 
#            | | | |                  | |
#   __ _  ___| |_| |__   ___  __ _  __| |
#  / _` |/ _ \ __| '_ \ / _ \/ _` |/ _` |
# | (_| |  __/ |_| | | |  __/ (_| | (_| |
#  \__, |\___|\__|_| |_|\___|\__,_|\__,_|
#   __/ |                                
#  |___/                                 
#
# description:	http header vulnerability analysis project
# github:	    https://github.com/httphacker
# email:	    httphacker@icloud.com
# website:	    http://httphacker.com
# twitter:	    @httphacker
# version:	    0.1

import sys
import urllib2

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

def has_colours(stream):
    if not hasattr(stream, "isatty"):
        return False
    if not stream.isatty():
        return False
    try:
        import curses
        curses.setupterm()
        return curses.tigetnum("colors") > 2
    except:
        return False

has_colours = has_colours(sys.stdout)

def printout(text, colour=WHITE):
        if has_colours:
                seq = "\x1b[1;%dm" % (30+colour) + text + "\x1b[0m"
                sys.stdout.write(seq)
        else:
                sys.stdout.write(text)

def headsplit(header, p):
  try:
    rahs = str(header).split(":",1)
    if int(p) == 0:
      return rahs[0]
    if int(p) == 1:
      return rahs[1]
  except:
    pass

def cchecks(xinfo, ahs):

  # via header
  if xinfo == "Via":
    printout('\t[!] Via proxy header: ' + ahs, RED) 
    printout('''
		- The server is utilizing Load balancers or a proxy.\n\n''', WHITE)
    

  # proxy auth basic
  if xinfo == "Proxy-Authenticate":
    if ash == "Basic":
      printout('\t[!] Base64 Proxy Authentication: ' + ahs, RED) 
      printout('''
		- The server is utilizing Basic Authentication.
		  This is a clear text and can be easily unencoded.
		  It is recommended to use other forms of authentication.\n\n''', WHITE)

  # get server information
  if xinfo == "Server":
    printout("\t[!] Server header: " + ahs+"\n", RED)
    print ""

  # powered by
  if xinfo == "X-Powered-By":
    printout ("\t[!] X-Powered-By: "+ahs+"\n", RED)
    print ""
  
  # asp version
  if xinfo == "X-AspNet-Version":
    printout("\t[!] ASP.net version: "+ahs+"\n", RED)
    print ""

  # date and time stamp informaiton disclosure
  if xinfo == "Date":
    printout('\t[!] Date timestamp disclosure: ' + ahs, RED) 
    printout('''
		- System time is represented in HTTP headers.
		  This information can be used to determine location 
		  of the device to plan their attacks when it is 
		  expected to have minimal or no users.
		  Saved cookies could be harvested and replayed 
		  impersonating legitimate users.\n\n''', WHITE)

  # Set-Cookie Persistent Cookies
  if xinfo == "Expires":
    printout('\t[!] Persistent Cookie Issues: '+ahs, RED) 
    printout('''
		- Persistent cookie on end users systems.
		  The recomended way to handle this issue is with session
		  cookies. If the expiration date is older then the 
		  local user system time/date, the cookie will be treated
		  as that of a session cookie.
		  Saved cookies could be harvested and replayed 
		  impersonating legitimate users.\n\n''', WHITE)

  # check x-xss-protection:
  if xinfo == 'X-XSS-Protection':
    if ahs == '1; mode=block':
      printout('\t(X-XSS-Protection) Cross-Site Scripting Protection is enforced.\n\n', GREEN)
      printout('\t\t[-] X-XSS-Protection: ' + ahs + '\n\n', CYAN)
    if ahs == "0":
      printout('\t[!] X-XSS-Protection Vulnerability ', RED) 
      printout('''
		- Server does not enforce XSS Protection.
		  The X-XSS-Protection Header setting is : '''+ahs+'''
		  Client may be vulnerable to Cross-Site Scripting Attacks.\n\n''', WHITE)
  else:
    pass

  # check x-frame-options:
  if xinfo == 'X-Frame-Options':
    if ahs != "" or None:
      printout('\t(X-Frame-Options) Cross-Frame Scripting Protection is enforced.\n\n', GREEN)
      printout('\t\t[-] X-Frame-Options: ' + ahs + '\n\n', CYAN)
    else:
      printout('\t[!] Vulnerability ', RED)
      printout('''
			- Server does not enforce XFS Protection.
			  The X-Frame-Options Header setting is either inadequate or missing.
			  Client may be vulnerable to Click-Jacking Attacks.\n\n''', WHITE)
  else:
    pass

  # check x-content-type-options:
  if xinfo == 'X-Content-Type-Options':
    if ahs == 'nosniff':
      printout('\t(X-Content-Type-Options) MIME-Sniffing Protection is enforced.\n\n', GREEN)
      printout('\t\t[-] X-Content-Type-Options: ' + ahs + '\n\n', CYAN)
    else:
      printout('\t[!] Vulnerability ', RED) 
      printout('- Server does not enforce MIME-Sniffing Protection.\nThe X-Content-Type-Options Header setting is either inadequate or missing.\nClient may be vulnerable to MIME-Sniffing Attacks.\n\n', WHITE)
  else:
    pass
  # check strict-transport-security:
  if xinfo == 'Strict-Transport-Security':
    if ahs != "":
      printout('\t(Strict-Transport-Security) HTTP over TLS/SSL is enforced.\n\n', GREEN)
      printout('\t\t[-] Strict-Transport-Security: ' + ahs + '\n\n', CYAN)
    else:
      printout('\t[!] Vulnerability ', RED)
      printout('- Server does not enforce HTTP over TLS/SSL Connections.\nThe Strict-Transport-Security Header setting is either inadequate or missing.\nClient may be vulnerable to Session Information Leakage.\n\n', WHITE)
  else:
    pass

  # check x-content-security-policy:
  if xinfo == 'X-Content-Security-Policy':
    if ahs != "":
      printout('(X-Content-Security-Policy) Content Security Policy is enforced.\n\n', GREEN)
      printout('\t\t[-] X-Content-Security-Policy: ' + ahs + '\n\n', CYAN)
    else:
      printout('\t[!] Vulnerability ', RED)
      printout('- Server does not enforce a Content Security Policy.\nThe X-Content-Security-Policy Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Site Scripting and Injection Attacks.\n\n', WHITE)
  else:
    pass

# check x-webkit-csp:
  if xinfo == 'X-WebKit-CSP':
    if ahs != "":
      printout('(X-WebKit-CSP) Content Security Policy is enforced.\n\n', GREEN)
      printout('\t\t[-] X-WebKit-CSP: ' + ahs + '\n\n', CYAN)
    else:
      printout('\t[!] Vulnerability ', RED)
      printout('- Server does not enforce a Content Security Policy.\nThe X-WebKit-CSP Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Site Scripting and Injection Attacks.\n\n', WHITE)
  else:
    pass

  # check access-control-allow-origin:
  if xinfo == 'Access-Control-Allow-Origin':
    if ahs != "":
      printout('(Access-Control-Allow-Origin) Access Control Policies are enforced.\n\n', GREEN)
      printout('\t\t[-] Access-Control-Allow-Origin: ' + ahs + '\n\n', CYAN)
    else:
      printout('\t[!] Vulnerability ', RED)
      printout('- Server does not enforce an Access Control Policy.\nThe Access-Control-Allow-Origin Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Domain Scripting Attacks.\n\n', WHITE)
  else:
    pass

  # check x-download-options:
  if xinfo == 'X-Download-Options':
    if ahs != '':
      printout('(X-Download-Options) File Download and Open Restriction Policies are enforced.\n\n', GREEN)
      printout('\t\t[-] X-Download-Options: ' + ahs + '\n\n', CYAN)
    else:
      printout('\t[!] Vulnerability ', RED)
      printout('- Server does not enforce a File Download and Open Policy.\nThe X-Download-Options Header setting is either inadequate or missing.\nClient may be vulnerable to Browser File Execution Attacks.\n\n', WHITE)
  else:
    pass

  # check cache-control:
  if xinfo == 'Cache-Control':
    if ahs != "": 
      ahss = str(ahs).split(",")
      c = 0
      for xahss in ahss:
        ahssl = len(ahss)-1
        if xahss in ["private", "no-cahce", "no-store", "must-revalidate"]:
          printout('\t(Cache-control) Private Content Cacheing is enforced.\n\n', GREEN)
          printout('\t\t[-] Cache-control: ' + ahs + '\n\n', CYAN)
          c +=1
          break
        else:
          if c == ahssl:
            printout('\t[!] Cache-Control Vulnerability ', RED)
            printout('''
		- Server does not enforce a Content Cacheing Policy.
		  The Cache-Control Header setting is either inadequate or missing.
		  Client may be vulnerable to Content Caching Attacks.\n\n''', WHITE)
          c +=1
  else:
    pass

  # check httponly
  if xinfo == "Set-Cookie":
    if ahs != "": 
      ahss = str(ahs).split(";")
      c = 0
      for xahss in ahss:
        ahssl = len(ahss)-1
        if str(xahss) == " httponly":
          printout('\t(Set-Cookie) HTTPonly flag is enabled.\n\n', GREEN)
          printout('\t\t[-] Set-Cookie: ' + str(ahss[0]) + '\n\n', CYAN)
          c+=1
          break
        else:
          if c == ahssl:
            printout('\t[!] Set-Cookie HTTPOnly Issue ', RED)
            ahsvs = str(ahs).split("=") 
            printout('''
		- '''+str(ahsvs[0])+''' Cookie does not utilize the httponly flag.
		  The httponly flag helps protect cookie session IDs from being 
		  acessed by javascript.
		  This only protects cookie data, not a mitigation to XSS\n\n''', WHITE)
          c += 1 
    else:
      pass
  else:
    pass
#
#
#



if len(sys.argv) < 2:
  print
  printout('Please provide a fully-qualified path!\n', RED)
  printout('Usage: python gethead.py path\n', WHITE)
  printout('Example: python gethead.py http://www.google.com\n\n', WHITE)
  sys.exit()
else:
  response = urllib2.urlopen(sys.argv[1])
  print 
  printout('HTTP Header Analysis for ' + sys.argv[1] + ':' + '\n\n', CYAN)

rinfo = response.info()
printout('\t[-] (RAW HEADERS)\n\n\n', GREEN)
print rinfo
for xrinfo in str(rinfo).split("\n"):
  try:
   sxi = headsplit(xrinfo, '0')
   ahs = str(headsplit(xrinfo, '1')).strip()
  #print sxi
  #print ahs
   cchecks(sxi,ahs)
  except:
    pass 
