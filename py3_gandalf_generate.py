#Python 3..

DEFAULT_TEMPLATE = "gandalfAgentTemplate-Windows-x64.exe"
DEFAULT_URL = "https://127.0.0.1"
DEFAULT_PROTO = "https"
DEFAULT_PSK = "gandalf"
DEFAULT_SLEEPMIN = "15"
DEFAULT_SLEEPMAX = "30"
DEFAULT_INACTIVEMULTIPLIER = "5"
DEFAULT_INACTIVETHRESHOLD = "6"
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"
DEFAULT_MAXRETRY = "99999"
DEFAULT_PADDING = "4096"
DEFAULT_PROXY = ""
DEFAULT_JA3 = ""
DEFAULT_HOSTHEADER = ""
DEFAULT_KILLDATE = "0"
DEFAULT_OUTPUT = "gandalfAgentPatched-Windows-x64.exe"

print ("\nPress enter for default values (shown as [value] to the left of the prompt)")

print ("\nEnter Template File Location:\n")

temptemplate = input('[' + DEFAULT_TEMPLATE + '] > ')
if (len(temptemplate) > 0):
   DEFAULT_TEMPLATE = temptemplate

gandalftemplate = open(DEFAULT_TEMPLATE, "rb")

print ("\nTemplate File Location Selection: " + DEFAULT_TEMPLATE)

print ("\nEnter Output File Location:\n")

tempoutput = input('[' + DEFAULT_OUTPUT + '] > ')
if (len(tempoutput) > 0):
   DEFAULT_OUTPUT = tempoutput

gandalfoutput = open(DEFAULT_OUTPUT, "wb")

print ("\nOutput File Location Selection: " + DEFAULT_OUTPUT)

print ("\nEnter Callback URL:\n")

tempurl = input('[' + DEFAULT_URL + '] > ')
if (len(tempurl) > 0):
    tempurl2 = tempurl.replace(" ", "")
    DEFAULT_URL = tempurl2

print ("\nCallback URL Selection: " + DEFAULT_URL)

print ("\nSelect Protocol:\n\n    [1] - https\n    [2] - http\n    [3] - http2\n    [4] - h2c\n    [5] - http3\n")

tempproto = input('[' + "1" + '] > ')
if (len(tempproto) > 0 and (tempproto == "1" or tempproto == "2" or tempproto == "3" or tempproto == "4" or tempproto == "5")):
    if (tempproto == "1"):
	    DEFAULT_PROTO = "https"
    elif (tempproto == "2"):
        DEFAULT_PROTO = "http "
    elif (tempproto == "3"):
        DEFAULT_PROTO = "h2   "
    elif (tempproto == "4"):
        DEFAULT_PROTO = "h2c  "
    elif (tempproto == "5"):
        DEFAULT_PROTO = "http3"
elif (len(tempproto) != 0):
    print ("Invalid input!")
    raise SystemExit
else:
    DEFAULT_PROTO = "https"

if (DEFAULT_PROTO == "h2   "):
    print ("\nProtocol Selection: http2")
else:
    print ("\nProtocol Selection: " + DEFAULT_PROTO)

print ("\nEnter PSK:\n")

temppsk = input('[' + DEFAULT_PSK + '] > ')
if (len(temppsk) > 0):
    DEFAULT_PSK = temppsk

print ("\nPSK Selection: " + DEFAULT_PSK)

print ("\nEnter Sleep Minimum (in seconds):\n")

tempsleepmin = input('[' + DEFAULT_SLEEPMIN + '] > ')
if (len(tempsleepmin) > 0):
    DEFAULT_SLEEPMIN = tempsleepmin

print ("\nSleep Minimum Selection: " + DEFAULT_SLEEPMIN + " seconds")

print ("\nEnter Sleep Maximum (in seconds):\n")

tempsleepmax = input('[' + DEFAULT_SLEEPMAX + '] > ')
if (len(tempsleepmax) > 0):
    DEFAULT_SLEEPMAX = tempsleepmax

print ("\nSleep Maximum Selection: " + DEFAULT_SLEEPMAX + " seconds")

print ("\nEnter Inactivity Multiplier (how much sleep times will be multiplied by when slowing down due to inactivity):\n")

tempinactivemultiplier = input('[' + DEFAULT_INACTIVEMULTIPLIER + '] > ')
if (len(tempinactivemultiplier) > 0):
   DEFAULT_INACTIVEMULTIPLIER = tempinactivemultiplier

print ("\nInactivity Multiplier Selection: " + DEFAULT_INACTIVEMULTIPLIER)

print ("\nEnter Inactivity Threshold (how many check-ins without operator input until agent goes inactive):\n")

tempinactivethreshold = input('[' + DEFAULT_INACTIVETHRESHOLD + '] > ')
if (len(tempinactivethreshold) > 0):
   DEFAULT_INACTIVETHRESHOLD = tempinactivethreshold

print ("\nInactivity Threshold Selection: " + DEFAULT_INACTIVETHRESHOLD)

print ("\nEnter User Agent String:\n")

tempua = input('[' + DEFAULT_UA + '] > ')
if (len(tempua) > 0):
   DEFAULT_UA = tempua

print ("\nUser Agent String Selection: " + DEFAULT_UA)

print ("\nEnter Max Retry Attempts (number of failed connection attempts before exiting):\n")

tempmaxretry = input('[' + DEFAULT_MAXRETRY + '] > ')
if (len(tempmaxretry) > 0):
   DEFAULT_MAXRETRY = tempmaxretry

print ("\nMax Retry Attempts Selection: " + DEFAULT_MAXRETRY)

print ("\nEnter Max Padding (maximum amount of random data in bytes to be added to each request):\n")

temppadding = input('[' + DEFAULT_PADDING + '] > ')
if (len(temppadding) > 0):
   DEFAULT_PADDING = temppadding

print ("\nMax Padding Selection: " + DEFAULT_PADDING)

print ("\nEnter Proxy Information (http://192.168.1.250:8080):\n")

tempproxy = input('[' + DEFAULT_PROXY + '] > ')
if (len(tempproxy) > 0):
   DEFAULT_PROXY = tempproxy

print ("\nProxy Information Selection: " + DEFAULT_PROXY)

print ("\nEnter JA3 String (JA3 signature used to generate a JA3 client):\n")

tempja3 = input('[' + DEFAULT_JA3 + '] > ')
if (len(tempja3) > 0):
   DEFAULT_JA3 = tempja3

print ("\nJA3 String Selection: " + DEFAULT_JA3)

print ("\nEnter Host Header (typically used with domain fronting):\n")

temphostheader = input('[' + DEFAULT_HOSTHEADER + '] > ')
if (len(temphostheader) > 0):
   DEFAULT_HOSTHEADER = temphostheader

print ("\nHost Header Selection: " + DEFAULT_HOSTHEADER)

print ("\nEnter Kill Date (Unix epoc format, 0 means no kill date):\n")

tempkilldate = input('[' + DEFAULT_KILLDATE + '] > ')
if (len(tempkilldate) > 0):
   DEFAULT_KILLDATE = tempkilldate

print ("\nKill Date Selection: " + DEFAULT_KILLDATE)

gandalfcontents = gandalftemplate.read()
gandalftemplate.close()

print ("Patching all selected values...")

replacementurl = DEFAULT_URL
if (len(replacementurl) < 200 ):
    urldifference = 200 - (len(replacementurl))
else:
    print ("Invalid input!")
    raise SystemExit

replacementurl += ' ' * urldifference
gandalfcontents = gandalfcontents.replace(b'Y'*200, str.encode(replacementurl))

gandalfcontents = gandalfcontents.replace(b"XXXXX", str.encode(DEFAULT_PROTO))

replacementpsk = DEFAULT_PSK
if (len(replacementpsk) < 200 ):
    pskdifference = 200 - (len(replacementpsk))
else:
    print ("Invalid input!")
    raise SystemExit

replacementpsk += ' ' * pskdifference
gandalfcontents = gandalfcontents.replace(b'W'*200, str.encode(replacementpsk))

if (len(DEFAULT_SLEEPMIN) < 18 ):
    sleepmindifference = 18 - (len(DEFAULT_SLEEPMIN))
else:
    print ("Invalid input!")
    raise SystemExit

replacementsleepmin = '0' * sleepmindifference
replacementsleepmin += DEFAULT_SLEEPMIN
gandalfcontents = gandalfcontents.replace(b'9'*18, str.encode(replacementsleepmin))

if (len(DEFAULT_SLEEPMAX) < 18 ):
    sleepmaxdifference = 18 - (len(DEFAULT_SLEEPMAX))
else:
    print ("Invalid input!")
    raise SystemExit

replacementsleepmax = '0' * sleepmaxdifference
replacementsleepmax += DEFAULT_SLEEPMAX
gandalfcontents = gandalfcontents.replace(b'8'*18, str.encode(replacementsleepmax))

if (len(DEFAULT_INACTIVEMULTIPLIER) < 18 ):
    multiplierdifference = 18 - (len(DEFAULT_INACTIVEMULTIPLIER))
else:
    print ("Invalid input!")
    raise SystemExit

replacementmultiplier = '0' * multiplierdifference
replacementmultiplier += DEFAULT_INACTIVEMULTIPLIER
gandalfcontents = gandalfcontents.replace(b'7'*18, str.encode(replacementmultiplier))

if (len(DEFAULT_INACTIVETHRESHOLD) < 18 ):
    thresholddifference = 18 - (len(DEFAULT_INACTIVETHRESHOLD))
else:
    print ("Invalid input!")
    raise SystemExit

replacementthreshold = '0' * thresholddifference
replacementthreshold += DEFAULT_INACTIVETHRESHOLD
gandalfcontents = gandalfcontents.replace(b'6'*18, str.encode(replacementthreshold))

replacementua = DEFAULT_UA
if (len(replacementua) < 200 ):
    uadifference = 200 - (len(replacementua))
else:
    print ("Invalid input!")
    raise SystemExit

replacementua += ' ' * uadifference
gandalfcontents = gandalfcontents.replace(b'Z'*200, str.encode(replacementua))

if (len(DEFAULT_MAXRETRY) < 18 ):
    maxretrydifference = 18 - (len(DEFAULT_MAXRETRY))
else:
    print ("Invalid input!")
    raise SystemExit

replacementmaxretry = '0' * maxretrydifference
replacementmaxretry += DEFAULT_MAXRETRY
gandalfcontents = gandalfcontents.replace(b'5'*18, str.encode(replacementmaxretry))

if (len(DEFAULT_PADDING) < 18 ):
    paddingdifference = 18 - (len(DEFAULT_PADDING))
else:
    print ("Invalid input!")
    raise SystemExit

replacementpadding = '0' * paddingdifference
replacementpadding += DEFAULT_PADDING
gandalfcontents = gandalfcontents.replace(b'4'*18, str.encode(replacementpadding))

replacementproxy = DEFAULT_PROXY
if (len(replacementproxy) < 200 ):
    proxydifference = 200 - (len(replacementproxy))
else:
    print ("Invalid input!")
    raise SystemExit

replacementproxy += ' ' * proxydifference
gandalfcontents = gandalfcontents.replace(b'V'*200, str.encode(replacementproxy))

replacementja3 = DEFAULT_JA3
if (len(replacementja3) < 200 ):
    ja3difference = 200 - (len(replacementja3))
else:
    print ("Invalid input!")
    raise SystemExit

replacementja3 += ' ' * ja3difference
gandalfcontents = gandalfcontents.replace(b'U'*200, str.encode(replacementja3))

replacementhostheader = DEFAULT_HOSTHEADER
if (len(replacementhostheader) < 200 ):
    hostheaderdifference = 200 - (len(replacementhostheader))
else:
    print ("Invalid input!")
    raise SystemExit

replacementhostheader += ' ' * hostheaderdifference
gandalfcontents = gandalfcontents.replace(b'T'*200, str.encode(replacementhostheader))

if (len(DEFAULT_KILLDATE) < 18 ):
    killdatedifference = 18 - (len(DEFAULT_KILLDATE))
else:
    print ("Invalid input!")
    raise SystemExit

replacementkilldate = '0' * killdatedifference
replacementkilldate += DEFAULT_KILLDATE
gandalfcontents = gandalfcontents.replace(b'0'*18, str.encode(replacementkilldate))

gandalfoutput.write(gandalfcontents)
gandalfoutput.close()

print ("Patching complete!\nFile written to: " + DEFAULT_OUTPUT)