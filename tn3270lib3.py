#!/usr/bin/env python3
# TN3270 Library based heavily on x3270 and python telnet lib
# Created by Phil "Soldier of Fortran" Young

import errno
import sys
import socket
import ssl
import select
import struct
import binascii
import math


# Tunable parameters
DEBUGLEVEL = 0 

# Telnet protocol commands
SE   = chr(240) # End of subnegotiation parameters
SB   = chr(250) # Sub-option to follow
WILL = chr(251) # Will; request or confirm option begin
WONT = chr(252) # Wont; deny option request
DO   = chr(253) # Do = Request or confirm remote option
DONT = chr(254) # Don't = Demand or confirm option halt
IAC  = chr(255) # Interpret as Command
SEND = chr(1)   # Sub-process negotiation SEND command
IS   = chr(0)   # Sub-process negotiation IS command


# TN3270 Telnet Commands
TN_ASSOCIATE  = chr(0)
TN_CONNECT    = chr(1)
TN_DEVICETYPE = chr(2)
TN_FUNCTIONS  = chr(3)
TN_IS         = chr(4)
TN_REASON     = chr(5)
TN_REJECT     = chr(6)
TN_REQUEST    = chr(7)
TN_RESPONSES  = chr(2)
TN_SEND       = chr(8)
TN_TN3270     = chr(40)
TN_EOR        = chr(239) # End of Record

# Supported Telnet Options
options = {
    'BINARY'  : chr(0),
    'EOR'     : chr(25),
    'TTYPE'   : chr(24),
    'TN3270'  : chr(40),
    'TN3270E' : chr(28)
}

supported_options = {
    chr(0)  : 'BINARY',
    chr(25) : 'EOR',
    chr(24) : 'TTYPE',
    chr(40) : 'TN3270',
    chr(28) : 'TN3270E'
}

# TN3270 Stream Commands: TCPIP
EAU   = chr(15)
EW    = chr(5)
EWA   = chr(13)
RB    = chr(2)
RM    = chr(6)
RMA   = ''
W     = chr(1)
WSF   = chr(17)
NOP   = chr(3)
SNS   = chr(4)
SNSID = chr(228)
# TN3270 Stream Commands: SNA
SNA_RMA   = chr(110)
SNA_EAU   = chr(111)
SNA_EWA   = chr(126)
SNA_W     = chr(241)
SNA_RB    = chr(242)
SNA_WSF   = chr(243)
SNA_EW    = chr(245)
SNA_NOP   = chr(3)
SNA_RM    = chr(246)


# TN3270 Stream Orders
SF  = chr(29)
SFE = chr(41)
SBA = chr(17)
SA  = chr(40)
MF  = chr(44)
IC  = chr(19)
PT  = chr(5)
RA  = chr(60)
EUA = chr(18)
GE  = chr(8)


# TN3270 Format Control Orders
NUL = chr(0)
SUB = chr(63)
DUP = chr(28)
FM  = chr(30)
FF  = chr(12)
CR  = chr(13)
NL  = chr(21)
EM  = chr(25)
EO  = chr(255)

# TN3270 Attention Identification (AIDS)
NO      = chr(0x60) # no aid
QREPLY  = chr(0x61) # reply
ENTER   = chr(0x7d) # enter
PF1     = chr(0xf1)
PF2     = chr(0xf2)
PF3     = chr(0xf3)
PF4     = chr(0xf4)
PF5     = chr(0xf5)
PF6     = chr(0xf6)
PF7     = chr(0xf7)
PF8     = chr(0xf8)
PF9     = chr(0xf9)
PF10    = chr(0x7a)
PF11    = chr(0x7b)
PF12    = chr(0x7c)
PF13    = chr(0xc1)
PF14    = chr(0xc2)
PF15    = chr(0xc3)
PF16    = chr(0xc4)
PF17    = chr(0xc5)
PF18    = chr(0xc6)
PF19    = chr(0xc7)
PF20    = chr(0xc8)
PF21    = chr(0xc9)
PF22    = chr(0x4a)
PF23    = chr(0x4b)
PF24    = chr(0x4c)
OICR    = chr(0xe6)
MSR_MHS = chr(0xe7)
SELECT  = chr(0x7e)
PA1     = chr(0x6c)
PA2     = chr(0x6e)
PA3     = chr(0x6b)
CLEAR   = chr(0x6d)
SYSREQ  = chr(0xf0)

# used for Structured Fields
AID_SF      = chr(0x88)
SFID_QREPLY = chr(0x81)

# TN3270 Code table to translate buffer addresses

code_table = [0x40, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
              0xC8, 0xC9, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
              0x50, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
              0xD8, 0xD9, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
              0x60, 0x61, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
              0xE8, 0xE9, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
              0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
              0xF8, 0xF9, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F]

# TN3270 Datastream Processing flags
NO_OUTPUT      = 0
OUTPUT         = 1
BAD_COMMAND    = 2
BAD_ADDRESS    = 3
NO_AID         = 0x60



# Header response flags.
NO_RESPONSE       = 0x00
ERROR_RESPONSE    = 0x01
ALWAYS_RESPONSE   = 0x02
POSITIVE_RESPONSE = 0x00
NEGATIVE_RESPONSE = 0x01

# Header data type names.
DT_3270_DATA    = 0x00
DT_SCS_DATA     = 0x01
DT_RESPONSE     = 0x02
DT_BIND_IMAGE   = 0x03
DT_UNBIND       = 0x04
DT_NVT_DATA     = 0x05
DT_REQUEST      = 0x06
DT_SSCP_LU_DATA = 0x07
DT_PRINT_EOJ    = 0x08

# Header response data.
POS_DEVICE_END             = 0x00
NEG_COMMAND_REJECT         = 0x00
NEG_INTERVENTION_REQUIRED  = 0x01
NEG_OPERATION_CHECK        = 0x02
NEG_COMPONENT_DISCONNECTED = 0x03

# Structured fields
# From x3270 sf.c
SF_READ_PART      = chr(0x01)    # read partition
SF_RP_QUERY       = chr(0x02)    # query
SF_RP_QLIST       = chr(0x03)    # query list
SF_RPQ_LIST       = chr(0x00)    # QCODE list
SF_RPQ_EQUIV      = chr(0x40)    # equivalent+ QCODE list
SF_RPQ_ALL        = chr(0x80)    # all
SF_ERASE_RESET    = chr(0x03)    # erase/reset
SF_ER_DEFAULT     = chr(0x00)    # default
SF_ER_ALT         = chr(0x80)    # alternate
SF_SET_REPLY_MODE = chr(0x09)    # set reply mode
SF_SRM_FIELD      = chr(0x00)    # field
SF_SRM_XFIELD     = chr(0x01)    # extended field
SF_SRM_CHAR       = chr(0x02)    # character
SF_CREATE_PART    = chr(0x0c)    # create partition
CPFLAG_PROT       = chr(0x40)    # protected flag
CPFLAG_COPY_PS    = chr(0x20)    # local copy to presentation space
CPFLAG_BASE       = chr(0x07)    # base character set index
SF_OUTBOUND_DS    = chr(0x40)    # outbound 3270 DS
SF_TRANSFER_DATA  = chr(0xd0)    # file transfer open request

# Data Transfer
# Host requests.
TR_OPEN_REQ         = 0x0012    # open request
TR_CLOSE_REQ        = 0x4112    # close request
TR_SET_CUR_REQ      = 0x4511    # set cursor request
TR_GET_REQ          = 0x4611    # get request
TR_INSERT_REQ       = 0x4711    # insert request
TR_DATA_INSERT      = 0x4704    # data to insert

# PC replies.
TR_GET_REPLY        = 0x4605    # data for get
TR_NORMAL_REPLY     = 0x4705    # insert normal reply
TR_ERROR_REPLY      = 0x08      # error reply (low 8 bits)
TR_CLOSE_REPLY      = 0x4109    # close acknowledgement

# Other headers.
TR_RECNUM_HDR       = 0x6306    # record number header
TR_ERROR_HDR        = 0x6904    # error header
TR_NOT_COMPRESSED   = 0xc080    # data not compressed
TR_BEGIN_DATA       = 0x61      # beginning of data

# Error codes.
TR_ERR_EOF          = 0x2200    # get past end of file
TR_ERR_CMDFAIL      = 0x0100    # command failed

DFT_BUF             = 4096      # Default buffer size
DFT_MIN_BUF         = 256       # Minimum file send buffer size
DFT_MAX_BUF         = 32768     # Max buffer size

# File Transfer Constants
FT_NONE       = 1   # No transfer in progress
FT_AWAIT_ACK  = 2   # IND$FILE sent, awaiting acknowledgement message



# TN3270E Negotiation Options

TN3270E_ASSOCIATE   = chr(0x00)
TN3270E_CONNECT     = chr(0x01)
TN3270E_DEVICE_TYPE = chr(0x02)
TN3270E_FUNCTIONS   = chr(0x03)
TN3270E_IS          = chr(0x04)
TN3270E_REASON      = chr(0x05)
TN3270E_REJECT      = chr(0x06)
TN3270E_REQUEST     = chr(0x07)
TN3270E_SEND        = chr(0x08)

# Global Vars
NEGOTIATING    = 0
CONNECTED      = 1
TN3270_DATA    = 2
TN3270E_DATA   = 3
# We only support 3270 model 2 which was 24x80.
#
# DEVICE_TYPE    = "IBM-3278-2"
#
DEVICE_TYPE    = "IBM-3279-2-E"
COLS           = 80 # hardcoded width.
ROWS           = 24 # hardcoded rows.
WORD_STATE     = ["Negotiating", "Connected", "TN3270 mode", "TN3270E mode"]
TELNET_PORT    = 23

# For easy debugging/printing:
telnet_commands = {
    SE   : 'SE',
    SB   : 'SB',
    WILL : 'WILL',
    WONT : 'WONT',
    DO   : 'DO',
    DONT : 'DONT',
    IAC  : 'IAC',
    SEND : 'SEND',
    IS   : 'IS'
}

telnet_options = {
    TN_ASSOCIATE  : 'ASSOCIATE',
    TN_CONNECT    : 'CONNECT',
    TN_DEVICETYPE : 'DEVICE_TYPE',
    TN_FUNCTIONS  : 'FUNCTIONS',
    TN_IS         : 'IS',
    TN_REASON     : 'REASON',
    TN_REJECT     : 'REJECT',
    TN_REQUEST    : 'REQUEST',
    TN_RESPONSES  : 'RESPONSES',
    TN_SEND       : 'SEND',
    TN_TN3270     : 'TN3270',
    TN_EOR        : 'EOR'
}

tn3270_options = {
    TN3270E_ASSOCIATE   :'TN3270E_ASSOCIATE',
    TN3270E_CONNECT     :'TN3270E_CONNECT',
    TN3270E_DEVICE_TYPE :'TN3270E_DEVICE_TYPE',
    TN3270E_FUNCTIONS   :'TN3270E_FUNCTIONS',
    TN3270E_IS          :'TN3270E_IS',
    TN3270E_REASON      :'TN3270E_REASON',
    TN3270E_REJECT      :'TN3270E_REJECT',
    TN3270E_REQUEST     :'TN3270E_REQUEST',
    TN3270E_SEND        :'TN3270E_SEND'
}


class TN3270:
    def __init__(self, host=None, port=0, timeout=10):

        self.debuglevel = DEBUGLEVEL
        self.host       = host
        self.port       = port
        self.timeout    = timeout
        self.eof        = 0
        self.sock       = None
        self._has_poll  = hasattr(select, 'poll')
        self.unsupported_opts = {}
        self.telnet_state   = 0 # same as TNS_DATA to begin with
        self.server_options = {}
        self.client_options = {} 
        self.sb_options     = ''
        self.connected_lu   = ''
        self.connected_dtype= ''
        # self.negotiated     = False
        self.first_screen   = False
        self.aid            = NO_AID  # initial Attention Identifier is No AID
        self.telnet_data    = ''
        self.tn_buffer      = ''
        self.raw_tn         = [] # Stores raw TN3270 'frames' for use
        self.state          = 0
        self.buffer_address = 0
        self.formatted      = False,

        # TN3270 Buffer Address Location
        self.buffer_addr = 0
        # TN3270 Cursor Tracking Location
        self.cursor_addr = 0
        self.screen          = []
        self.printableScreen = []
        self.header          = []

        # TN3270 Buffers
        self.buffer         = []
        self.fa_buffer      = []
        self.output_buffer  = []
        self.overwrite_buf  = []
        self.header_sequence = 0
        # TN3270E Header variables
        self.tn3270_header = {
            'data_type'     : '',
            'request_flag'  : '',
            'response_flag' : '',
            'seq_number'    : ''
        }

        # File Transfer
        self.ft_buffersize = 0
        self.ft_state = FT_NONE

        if host is not None:
            self.initiate(host, port, timeout)

    def connect(self, host, port=0, timeout=30):
        """Connects to a TN3270 Server. aka a Mainframe!"""
        self.ssl = False
        if not port:
            port = TELNET_PORT
        self.host = host
        self.port = port
        self.timeout = timeout
        # Try SSL First
        try:
            self.msg(1, 'Trying SSL/TSL')
            non_ssl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock = ssl.wrap_socket(sock=non_ssl, cert_reqs=ssl.CERT_NONE)
            ssl_sock.settimeout(timeout)
            ssl_sock.connect((host, port))
            self.sock = ssl_sock
        except (ssl.SSLError, socket.error) as e:
            non_ssl.close()
            self.msg(1, 'SSL/TLS Failed. Trying Plaintext')
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(timeout)
                self.sock.connect((host, port))
            except Exception as e:
                self.msg(1, 'Error: %r', e)
                return False
        except Exception as e:
            self.msg(1, '[SSL] Error: %r', e)
            return False
        
        return True

    def __del__(self):
        """Destructor ## close the connection."""
        self.disconnect()

    def msg(self, level, msg, *args):
        """Print a debug message, when the debug level is > 0.

        If extra arguments are present, they are substituted in the
        message using the standard string formatting operator.

        """
        if self.debuglevel >= level:
            print('TN3270(%s,%s):' % (self.host, self.port), end=' ')
            if args:
                print(msg % args)
            else:
                print(msg)

    def set_debuglevel(self, debuglevel=1):
        """Set the debug level.

        The higher it is, the more debug output you get (on sys.stdout).
        So far only levels 1 (verbose) and 2 (debug) exist.

        """
        self.debuglevel = debuglevel

    def set_LU(self, LU):
        """ Sets an LU to use on connection """
        self.connected_lu = LU

    def disable_enhanced(self, disable=True):
        self.msg(1, 'Disabling TN3270E Option')
        if disable:
            self.unsupported_opts[chr(40)] = 'TN3270'
        else:
            self.unsupported_opts.pop('TN3270', None)

    def disconnect(self):
        """Close the connection."""
        sock = self.sock
        self.sock = 0
        if sock:
            sock.close()

    def get_socket(self):
        """Return the socket object used internally."""
        return self.sock

    def send_data(self, data):
        """Sends raw data to the TN3270 server """
        self.msg(2, "send %r", data)
        self.sock.sendall(data.encode())

    def recv_data(self):
        """ Receives 256 bytes of data; blocking"""
        self.msg(2, "Getting Data")
        buf = self.sock.recv(256)
        self.msg(2, "Got Data: %r", buf)
        return buf.decode()

    def DECODE_BADDR(self, byte1, byte2):
        """ Decodes Buffer Addresses.
            Buffer addresses can come in 14 or 12 (this terminal doesn't support 16 bit)
            this function takes two bytes (buffer addresses are two bytes long) and returns
            the decoded buffer address."""
        if (byte1 & 0xC0) == 0:
            return (((byte1 & 0x3F) << 8) | byte2) 
        else:
            return ((byte1 & 0x3F) << 6) | (byte2 & 0x3F)  

    def ENCODE_BADDR(self, address):
        """ Encodes Buffer Addresses """
        b1 = struct.pack(">B", code_table[((address >> 6) & 0x3F)])
        b2 = struct.pack(">B", code_table[(address & 0x3F)])
        return b1 + b2

    def BA_TO_ROW(self, addr):
        """ Returns the current row of a buffer address """
        return math.ceil((addr / COLS) + 0.5)

    def BA_TO_COL(self, addr):
        """ Returns the current column of a buffer address """
        return addr % COLS

    def INC_BUF_ADDR(self, addr):
        """ Increments the buffer address by one """
        return ((addr + 1) % (COLS * ROWS))

    def DEC_BUF_ADDR(self, addr):
        """ Decreases the buffer address by one """
        return ((addr + 1) % (COLS * ROWS))

    def check_tn3270(self, host, port=0, timeout=3):
        """ Checks if a host & port supports TN3270 """
        if not port:
            port = TELNET_PORT
        try:
            non_ssl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock = ssl.wrap_socket(sock=non_ssl, cert_reqs=ssl.CERT_NONE)
            ssl_sock.settimeout(timeout)
            ssl_sock.connect((host, port))
            sock = ssl_sock
        except ssl.SSLError as e:
            non_ssl.close()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
            except Exception as e:
                self.msg(1, 'Error: %r', e)
                return False
        except Exception as e:
            self.msg(1, 'Error: %r', e)
            return False

        data = sock.recv(256).decode()
        if data == IAC + DO + options['TN3270']:
            sock.close()
            return True
        elif data == IAC + DO + options['TTYPE']:
            sock.sendall((IAC + WILL + options['TTYPE']).encode())
            data = sock.recv(256).decode()
            if data != IAC + SB + options['TTYPE'] + SEND + IAC + SE or data == '':
                return False
            sock.sendall((IAC + SB + options['TTYPE'] + IS + DEVICE_TYPE + IAC + SE).encode())
            data = sock.recv(256).decode()
            if data[0:2] == IAC + DO:
                sock.close()
                return True
        return False

    def initiate(self, host, port=0, timeout=5):
        """ Initiates a TN3270 connection until it gets the first 'screen' """
        # if not self.check_tn3270(host, port):
        #    return False
        if not self.connect(host, port, timeout):
            return False

        self.client_options = {}
        self.server_options = {}
        self.state = NEGOTIATING
        self.first_screen = False

        while not self.first_screen:
            self.telnet_data = self.recv_data()
            self.msg(2, "Got telnet_data: %r", self.telnet_data)
            r = self.process_packets()
            if not r: 
                return False
        return True

    def get_data(self):
        """ Gets the tn3270 buffer currently on the stack """
        status = True
        self.first_screen = False
        while not self.first_screen and status:
            try:
                self.telnet_data = self.recv_data()
                self.process_packets()
            except socket.timeout as e:
                err = e.args[0]
                if err == 'timed out':
                    # sleep(1)
                    self.msg(1, "recv timed out! We're done here")
                    break
            except socket.error as e:
                err = e.args[0]
                if 'timed out' in err: # This means the SSL socket timed out, not a regular socket so we catch it here
                    self.msg(1, "recv timed out! We're done here")
                    break
                # Something else happened, handle error, exit, etc.
                self.msg(1, "Get Data Socket Error Received: %r", e)
                
    def get_all_data(self):
        """ Mainframes will often send a 'confirmed' screen before it sends
            the screen we care about, this function clumsily gets all screens
            sent so far """
        self.first_screen = False
        self.sock.settimeout(2)
        count = 0
        while True and count <= 200:
            try:
                self.telnet_data = self.recv_data()
                                
                # Needed when mainframe closes socket on us
                if len(self.telnet_data) > 0:
                    self.msg(1, "Recv'd %i bytes", len(self.telnet_data))
                else:
                    count += 1
                    if count % 100: self.msg(1, 'Receiving 0 bytes')
                                    
                self.process_packets()
            except socket.timeout as e:
                err = e.args[0]
                if err == 'timed out':
                    # sleep(1)
                    self.msg(1, "recv timed out! We're done here")
                    break
            except socket.error as e:
                # Something else happened, handle error, exit, etc.
                self.msg(1, "Error Received: %r", e)
                break
        self.sock.settimeout(None)

    def process_packets(self):
        """ Processes Telnet data """
        for i in self.telnet_data:
            self.msg(3, "Processing: %r", i)
            r = self.ts_processor(i)
            if not r: return False
            self.telnet_data = '' # once all the data has been processed we clear out the buffer
        return True

    def ts_processor(self, data):
        """ Consumes/Interprets Telnet/TN3270 data """
        TNS_DATA   = 0
        TNS_IAC    = 1
        TNS_WILL   = 2
        TNS_WONT   = 3
        TNS_DO     = 4
        TNS_DONT   = 5
        TNS_SB     = 6
        TNS_SB_IAC = 7
        DO_reply   = IAC + DO
        DONT_reply = IAC + DONT
        WILL_reply = IAC + WILL
        WONT_reply = IAC + WONT

        # self.msg('State is: %r', self.telnet_state)
        if self.telnet_state == TNS_DATA:
            if data == IAC:
                ## got an IAC
                self.telnet_state = TNS_IAC
                return True
            self.store3270(data)
        elif self.telnet_state == TNS_IAC:
            if data == IAC:
                ## insert this 0xFF in to the buffer
                self.store3270(data)
                self.telnet_state = TNS_DATA
            elif data == TN_EOR:
                ## we're at the end of the TN3270 data
                ## let's process it and see what we've got
                ## but only if we're in 3270 mode
                if self.state == TN3270_DATA or self.state == TN3270E_DATA:
                    self.process_data()
                self.telnet_state = TNS_DATA
            elif data == WILL: self.telnet_state = TNS_WILL
            elif data == WONT: self.telnet_state = TNS_WONT
            elif data == DO  : self.telnet_state = TNS_DO
            elif data == DONT: self.telnet_state = TNS_DONT
            elif data == SB  : 
                self.telnet_state = TNS_SB
                self.sb_options = ''
        elif self.telnet_state == TNS_WILL:
            if data in supported_options and not (data in self.unsupported_opts):
                self.msg(1, "<< IAC WILL %s", supported_options[data])
                if not self.server_options.get(data, False): ## if we haven't already replied to this, let's reply
                    self.server_options[data] = True
                    self.send_data(DO_reply + data)
                    self.msg(1, ">> IAC DO %s", supported_options[data])
                    self.in3270()
            else:
                self.send_data(DONT_reply + data)
                self.msg(1, ">> IAC DONT %r", data)
            self.telnet_state = TNS_DATA
        elif self.telnet_state == TNS_WONT:
            if self.server_options.get(data, False):
                self.server_options[data] = False
                self.send_data(DONT_reply + data)
                self.msg(1, "Sent WONT Reply %r", data)
                self.in3270()
            self.telnet_state = TNS_DATA
        elif self.telnet_state == TNS_DO:
            if data in supported_options and not (data in self.unsupported_opts):
                self.msg(1, "<< IAC DO %s", supported_options[data])
                if not self.client_options.get(data, False):
                    self.client_options[data] = True
                    self.send_data(WILL_reply + data)
                    self.msg(1, ">> IAC WILL %s", supported_options[data])
                    self.in3270()
            else:
                self.send_data(WONT_reply + data)
                self.msg(1, "Unsupported 'DO'.")
                if data in options:
                    self.msg(1, ">> IAC WONT %s", options[data])
                else:
                    self.msg(1, ">> IAC WONT %r", data)
            self.telnet_state = TNS_DATA
        elif self.telnet_state == TNS_DONT:
            if self.client_options.get(data, False):
                self.client_options[data] = False
                self.send_data(WONT_reply + data)
                self.msg(1, ">> IAC DONT %r", data)
                self.in3270()
            self.telnet_state = TNS_DATA
        elif self.telnet_state == TNS_SB:
            if data == IAC:
                self.telnet_state = TNS_SB_IAC
            else:
                self.sb_options = self.sb_options + data
        elif self.telnet_state == TNS_SB_IAC:
            # self.msg(1,"<< IAC SB")
            self.sb_options = self.sb_options + data
            if data == SE:
                # self.msg(1,"Found 'SE' %r", self.sb_options)
                self.telnet_state = TNS_DATA
                if self.state != TN3270E_DATA:
                    phrase = ''
                    for i in self.sb_options: 
                        if i in telnet_options: phrase += telnet_options[i] + ' '
                        elif i in telnet_commands: phrase += telnet_commands[i] + ' '
                        elif i in supported_options: phrase += supported_options[i] + ' '
                        else: phrase += i + ' '
                    self.msg(1, "<< IAC SB %s", phrase)
                if (self.sb_options[0] == options['TTYPE'] and
                    self.sb_options[1] == SEND):
                    self.msg(1, ">> IAC SB TTYPE IS DEVICE_TYPE IAC SE")
                    self.send_data(IAC + SB + options['TTYPE'] + IS + DEVICE_TYPE + IAC + SE)
                elif self.client_options.get(options['TN3270'], False) and self.sb_options[0] == options['TN3270']:
                    if not self.negotiate_tn3270():
                        return False
        return True

    def negotiate_tn3270(self):
        """ Negotiates TN3270E Options. Which are different than Telnet 
            starts if the server options requests IAC DO TN3270 """
        # self.msg(1,"TN3270E Option Negotiation")
        TN3270_REQUEST = {
            chr(0) : 'BIND_IMAGE',
            chr(1) : 'DATA_STREAM_CTL',
            chr(2) : 'RESPONSES',
            chr(3) : 'SCS_CTL_CODES',
            chr(4) : 'SYSREQ'
        }

        phrase = ''
        tn_request = False

        for i in self.sb_options:
            if tn_request and i in TN3270_REQUEST:
                phrase += TN3270_REQUEST[i] + ' '
                tn_request = False
            elif i in tn3270_options: 
                phrase += tn3270_options[i] + ' '
                if i == TN3270E_REQUEST: tn_request = True
            elif i in telnet_options: phrase += telnet_options[i] + ' '
            elif i in telnet_commands: phrase += telnet_commands[i] + ' '
            elif i in supported_options: phrase += supported_options[i] + ' '
            else: phrase += i + ' '
        self.msg(1, "<< IAC SB %s",sf_cmd[3:fieldlen])
            elif wsf_cmd[2] ==  SF_TRANSFER_DATA:   # File transfer data
                self.msg(1, "[WSF] Structured Field File Transfer Data")
                self.file_transfer(wsf_cmd[:fieldlen])
            else:
                self.msg(1, "[WSF] unsupported ID", wsf_cmd[2])
                rv_this = BAD_COMMAND
            wsf_cmd = wsf_cmd[fieldlen:]
            bufflen = bufflen - fieldlen

    def read_partition(self, data):
        """ Structured field read partition """
        partition = data[0]
        if len(data) < 2:
            self.msg(1, "[WSF] error: field length %d too short", len(data))
            return BAD_COMMAND
        self.msg(1, "[WSF] Partition ID " + ''.join(hex(ord(n)) for n in data[0]))
        if data[1] == SF_RP_QUERY:
            self.msg(1, "[WSF] Read Partition Query")
            if partition != chr(0xff):
                self.msg(1, "Invalid Partition ID: %r", partition)
                return BAD_COMMAND
            # this ugly thing passes the query options
            # I hate it but its better than actually writing query options
            # Use Wireshark to see what exactly is happening here
            query_options = binascii.unhexlify(
                        "88000e81808081848586878895a1a60017818101000050001801000a0" +
                        "2e50002006f090c07800008818400078000001b81858200090c000000" +
                        "000700100002b900250110f103c3013600268186001000f4f1f1f2f2f" +
                        "3f3f4f4f5f5f6f6f7f7f8f8f9f9fafafbfbfcfcfdfdfefeffffffff00" +
                        "0f81870500f0f1f1f2f2f4f4f8f800078188000102000c81950000100" +
                        "010000101001281a1000000000000000006a3f3f2f7f0001181a6000" +
                        "00b01000050001800500018ffef")
            if self.state == TN3270E_DATA: query_options = (b"\x00" * 5) + query_options
            self.send_data(query_options.decode('latin1'))
        return

    def outbound_ds(self, data):
        """ Does something with outbound ds """
        if len(data) < 2:
            self.msg(1, "[WSF] error: field length %d too short", len(data))
            return BAD_COMMAND
        self.msg(1, "[WSF] Outbound DS value " + ''.join(hex(ord(n)) for n in data[0]))
        if struct.unpack(">B", data[0])[0] != 0:
            self.msg(1, "OUTBOUND_DS: Position 0 expected 0 got %s", data[0])

        if data[1] == SNA_W:
            self.msg(1, "       - Write ")
            self.process_write(data[1:]) # skip the type value when we pass to process write
        elif data[1] == SNA_EW:
            self.msg(1, "       - Erase/Write")
            self.clear_screen()
            self.process_write(data[1:])
        elif data[1] == SNA_EWA:
            self.msg(1, "       - Erase/Write/Alternate")
            self.clear_screen()
            self.process_write(data[1:])
        elif data[1] == SNA_EAU:
            self.msg(1, "       - Erase all Unprotected")
            self.clear_unprotected()
        else:
            self.msg(1, "unknown type "+ ''.join(hex(ord(n)) for n in data[0]))

    def erase_reset(self, data):
        """ Process Structured Field Erase Reset command """
        """ To Do: Add seperate paritions"""
        if data[1] == SF_ER_DEFAULT or data[1] == SF_ER_ALT:
            self.clear_screen()
        else:
            self.msg(1, "Error with data type in erase_reset: %s", data[1])


    def file_transfer(self, data):
        """ Handles Write Structured Fields file transfer requests 
            based on ft_dft_data.c and modified for this library """

        if self.ft_state == FT_NONE:
            return

        length = data[0:2]
        command = data[2]
        request_type = data[3:5]
        if len(data) > 5:
            compress_indicator = data[5:7]
            begin_data = data[7]
            data_len = data[8:10]
            received_data = data[10:]

        data_length = self.ret_16(length)
        data_type   = self.ret_16(request_type)
        if data_type == TR_OPEN_REQ:
            
            if data_length == 35:
                name = received_data[18:]
                # name = ""
                self.msg(1, "[WSF] File Transfer: Open Recieved: Message: %s", name)
            elif data_length == 41:
                name = received_data[24:]
                recsz = self.ret_16(received_data[20:22])
                self.msg(1, "[WSF] File Transfer: Message Received: %s, Size: %d", name, recsz)
            else:
                self.abort(TR_OPEN_REQ)
            
            if name == "FT:MSG ":
                self.message_flag = True
            else:
                self.message_flag = False
            
            self.dft_eof = False
            self.recnum = 1
            self.dft_ungetc_count = 0
            self.msg(1, "[WSF] File Transfer: Sending Open Acknowledgement")
            self.output_buffer = []
            self.output_buffer.append(AID_SF)
            self.output_buffer.append(self.set_16(5))
            self.output_buffer.append(SF_TRANSFER_DATA)
            self.output_buffer.append(self.set_16(9))
            # Send the acknowledgement package
            self.send_tn3270(self.output_buffer)

        elif data_type == TR_DATA_INSERT:
            self.msg(1, "[WSF] File Transfer: Data Insert")
            my_len = data_length - 5

            if self.message_flag:
                if received_data[0:7] == "TRANS03":
                    self.msg(1, "[WSF] File Transfer: File Transfer Complete!")
                    self.msg(1, "[WSF] File Transfer: Message: %s", received_data.strip())
                    self.ft_state = FT_NONE
                else:
                    self.msg(1, "[WSF] File Transfer: ERROR ERROR ERROR. There was a problem.")
                    self.msg(1, "[WSF] File Transfer: Message: %s", received_data)
                    self.ft_state = FT_NONE
            elif (my_len > 0):
                # We didn't get a message so it must be data!
                self.msg(1, "[WSF] File Transfer Insert: record number: %d | bytes: %d", self.recnum, my_len)
                bytes_writen = 0
                for i in received_data:
                    if self.ascii_file and (i == "\r" or i == chr(0x1a)):
                        continue
                    else:
                        bytes_writen += 1
                        self.file.write(i)
                self.msg(1, "[WSF] File Transfer Insert: Bytes Writen: %d", bytes_writen)
            self.msg(1, "[WSF] File Transfer Insert: Data Ack: record number: %d", self.recnum)
            self.output_buffer = []
            self.output_buffer.append(AID_SF)
            self.output_buffer.append(self.set_16(11))
            self.output_buffer.append(SF_TRANSFER_DATA)
            self.output_buffer.append(self.set_16(TR_NORMAL_REPLY))
            self.output_buffer.append(self.set_16(TR_RECNUM_HDR))
            self.output_buffer.append(self.set_32(self.recnum))
            self.recnum = self.recnum + 1
            # Send the acknowledgement package
            self.send_tn3270(self.output_buffer)

        elif data_type == TR_GET_REQ:
            self.msg(1, "[WSF] File Transfer: Get Data")

            total_read = 0
            temp_buf = []
            # Alright lets send some data!
            if self.ft_buffersize == 0:
                self.ft_buffersize = DFT_BUF

            if self.ft_buffersize > DFT_MAX_BUF:
                self.ft_buffersize = DFT_MAX_BUF
            elif self.ft_buffersize < DFT_MIN_BUF:
                self.ft_buffersize = DFT_MIN_BUF

            numbytes = self.ft_buffersize - 27 # how many bytes can we send
            self.msg(1, "[WSF] File Transfer Current Buffer Size: %d", self.ft_buffersize)
            self.output_buffer = [] # skip the header values for now
            self.output_buffer.append(AID_SF)
            self.output_buffer.append("") # blank size for now
            self.output_buffer.append("")
            self.output_buffer.append(SF_TRANSFER_DATA)

            while (not self.dft_eof) and (numbytes > 0):
                if self.ascii_file: # Reading an ascii file and replacing NL with LF/CR
                    self.msg(1, "[WSF] File Transfer ASCII: Reading one byte from %s", self.filename)
                    # Reads one byte from the file
                    # replace new lines with linefeed/carriage return
                    c = self.file.read(1)
                    if c == "":
                        self.dft_eof = True
                        break
                    if c == "\n":
                        temp_buf.append("\r")
                        temp_buf.append("\n")
                    else:
                        temp_buf.append(c)
                    numbytes = numbytes - 1
                    total_read = total_read + 1
                else:
                    self.msg(1, "[WSF] File Transfer Binary: Reading one byte from %s", self.filename)
                    # Reads one byte from the file
                    # replace new lines with linefeed/carriage return
                    c = self.file.read(1)
                    if c == "":
                        self.dft_eof = True
                        break
                    else:
                        temp_buf.append(c)
                    numbytes = numbytes - 1
                    total_read = total_read + 1
            if(total_read > 0):
                self.msg(1, "[WSF] File Transfer: Record Number: %d | Sent %d bytes", self.recnum, total_read)
                self.output_buffer.append(self.set_16(TR_GET_REPLY))
                self.output_buffer.append(self.set_16(TR_RECNUM_HDR))
                self.output_buffer.append(self.set_32(self.recnum))
                self.recnum = self.recnum + 1
                self.output_buffer.append(self.set_16(TR_NOT_COMPRESSED))
                self.output_buffer.append(chr(TR_BEGIN_DATA))
                self.output_buffer.append(self.set_16(total_read + 5))
                self.output_buffer.extend(temp_buf)
            else:
                self.msg(1, "[WSF] File Transfer: EOF")
                self.output_buffer.append(self.HIGH8(TR_GET_REQ))
                self.output_buffer.append(chr(TR_ERROR_REPLY))
                self.output_buffer.append(self.set_16(TR_ERROR_HDR))
                self.output_buffer.append(self.set_16(TR_ERR_EOF))
                self.dft_eof = True

            # Set the length now
            o_len = 0
            for i in self.output_buffer:
                if len(i) == 0:
                    o_len += 1
                else:
                    o_len += len(i)
            t_len = self.set_16(o_len-1) # minus one because we shouldn't count AID_SF
            self.output_buffer[1] = t_len[0]
            self.output_buffer[2] = t_len[1]
            self.send_tn3270(self.output_buffer)
        elif data_type == TR_CLOSE_REQ:
            self.msg(1, "[WSF] Close Request")
            self.output_buffer = []
            self.output_buffer.append(AID_SF)
            self.output_buffer.append(self.set_16(5))
            self.output_buffer.append(SF_TRANSFER_DATA)
            self.output_buffer.append(self.set_16(TR_CLOSE_REPLY))
            self.send_tn3270(self.output_buffer)
        elif data_type == TR_INSERT_REQ:
            self.msg(1, "[WSF] File Transfer: Insert") # We literally don't do anything

        elif data_type == TR_SET_CUR_REQ:
            self.msg(1, "[WSF] File Transfer: Set Cursor") # We don't do anything here either

    def ret_16(self, value):
        """ unpacks 3270 byte order """
        byte1 = struct.unpack(">B", value[0])[0]
        byte2 = struct.unpack(">B", value[1])[0]
        return byte2 + (byte1 << 8)

    def set_16(self, value):
        """ packs 3270 byte order """
        b1 = struct.pack(">B", (value & 0xFF00) >> 8)
        b2 = struct.pack(">B", (value & 0xFF))
        return (b1 + b2)

    def set_32(self, value):
        """ converts number in to 4 bytes for structured fields """
        b1 = struct.pack(">B", (value & 0xFF000000) >> 24)
        b2 = struct.pack(">B", (value & 0xFF0000) >> 16)
        b3 = struct.pack(">B", (value & 0xFF00) >> 8)
        b4 = struct.pack(">B", (value & 0xFF))
        return b
