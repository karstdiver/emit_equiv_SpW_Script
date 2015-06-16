#!/usr/bin/env python

"""e


This script is intended to read DDP UUT's logfiles and generate
equivalent DDP SpW commanding script.
"""

__version__ = "0.5"
__author__ = "Karst Diver"

import sys
import csv
import optparse
import time
import datetime
import re

USAGE = "%prog [options] output_script_file input_csv_log_file..."
VERSION = "%prog v" + __version__

# G L O B A L  V A R I A B L E S
ddpComment    = '# '    # comment string used in ddp script files
debugFlag     = False   # True == output debug statements (see command line)
verboseFlag   = False   # True == output verbose statmeents (see command line)

scriptOutFile = -1      # global for use in script() output funtion

csvHeaderDict = {}      # key==header column name  value==index

toDDPAddress   = "0xF0" # DDP unit's logical address
fromDDPAddress = "0x80"

fileSkipRange  = [114006, 122925]   # [file1, file2] files specific skip of SpW commands not of interest

previousDDPToTs   = -1  # for to DDP SpW command delta time
previousTODTs     = -1  # for TOD_PULSE delta time

totalLoglineCount = 0   # total number of logfile lines read
totalDDPlineCount = 0   # total number of logfile lines that are ddp SpW commands
totalDDPlineToCount    = 0  # To==F0 From==80  total to line count
totalDDPlineWrCount    = 0  # To==F0 From==80  write reply lines
totalDDPlineWcCount    = 0  # To==F0 From==80  write command lines
totalDDPlineFromCount  = 0  # To==80 From==F0
totalTODPulselineCount = 0
totalMemDumpSeqCount   = 0  # how many memory dump sequences processed
totalMemDumpStrCount   = 0  # how many memory dump start commands processed
totalMemDumpEndCount   = 0  # how many memory dump end   commands processed

inMemDumpState  = False  # True== in a memory dump command sequence
memDumpStartTs  = 0      # timestamp of 1st memory dump start command

# F U N C T I O N  D E C L A R A T I O N S
def parse_options():
    parser = optparse.OptionParser(usage=USAGE, version=VERSION)

    parser.add_option("-f", "--field",
            action="append", type="int",
            default=[], dest="fields",
            help="Field no. to cut (multiple allowed)")

    parser.add_option("-s", "--skip",
            action="append", type="int",
            default=[], dest="skip",
            help="Specify records to skip (multiple allowed)")

    parser.add_option("-d", "--debug",
            action="store_true",
            default=False, dest="debug",
            help="Turn on debug outputs (generates lots of logfile output)")

    parser.add_option("-v", "--verbose",
            action="store_true",
            default=False, dest="verbose",
            help="Turn on verbose outputs")

    parser.add_option("-q", "--quite",
            action="store_false",
            default=False, dest="verbose",
            help="Turn off verbose outputs")

    opts, args = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        raise SystemExit, 1

    return opts, args

def processCommandLine():
    global debugFlag
    global verboseFlag

    opts, args = parse_options()

    debugFlag   = opts.debug     # set flag based on command line
    verboseFlag = opts.verbose   # set flag based on command line

    debug("debug   flag %s" % str(debugFlag))
    debug("verbose flag %s" % str(verboseFlag))

    return opts, args

def openOutputFile(filename):
    debug("output filename: " + filename)

    if filename == "-":
       f = sys.stdout
    else:
       try:
           f = open(filename, "w")
       except:
           error("unable to open output file: %s" % filename)
       finally:
           debug("Opened output file: %s" % filename)

    return f

def openInputFile(filename):
    debug("input filename: " + filename)

    if filename == "-":
        f = sys.stdin
    else:
        try:
           f = open(filename, "rU")
        except:
           error("unable to open input file: %s" % filename)
        finally:
           debug("Opened input file: %s" % filename)

    return f

def closeFile(f, filename):
    try:
        close(f)
    except:
        debug("unable to close file: %s" % filename)
    finally:
        debug("Closing file: %s" % f)

def generate_rows(f):
    global csvHeaderDict         # this function builds this from logfile
    global totalLoglineCount     # funtion only deals with all logfile lines

    csvHeaderDict['To'] = -1          # initial value for no header yet seen

    debug("Starting generate_rows generator")

    sniffer = csv.Sniffer()
    dialect = sniffer.sniff(f.readline())
    f.seek(0)

    reader = csv.reader(f, dialect)
    for line in reader:

        # P R O C E S S  H E A D E R  L I N E
        if csvHeaderDict['To'] < 0:
           if re.search(r'To', str(line), re.M):

               # build dictionary of header column indices
               for i in range(len(line)):
                  line[i] = line[i].replace(' ', '_') # remove space from header
                  csvHeaderDict[line[i]] = line.index(line[i])

               debug("csvHeaderDict: " + str(csvHeaderDict))
               script(ddpComment + \
                      "csvHeader: " + str(csvHeaderDict))

               verbose("csv header line: %s" % str(line))
               script (ddpComment + \
                       "csv header line: %s" % str(line))

        totalLoglineCount += 1    # we see all logfile lines here

        # Y I E L D  A L L  L O G  L I N E S
        yield line  # return all log rows

def script(scriptLine):  # emit a ddp script line
    global scriptOutFile 
    print >> scriptOutFile, scriptLine

def debug(debugLine):  # emit a debug line
    global debugFlag
    if debugFlag: print ddpComment + debugLine

def verbose(verboseLine):  # emit a verbose information line
    global verboseFlag
    if verboseFlag: print ddpComment + verboseLine

def error(errorLine):  # emit a error line and exit
    print "Error: " + errorLine
    raise SystemExit, 1

def displayPreamble():
    verbose("start time: " + str(datetime.datetime.now()))

def displayPostamble():
    global totalLoglineCount       # total number of logfile lines read
    global totalDDPlineCount       # total number of logfile lines that are ddp SpW commands
    global totalDDPlineToCount
    global totalDDPlineWrCount
    global totalDDPlineWcCount
    global totalDDPlineFromCount
    global totalTODPulselineCount
    global totalMemDumpSeqCount
    global totalMemDumpStrCount
    global totalMemDumpEndCount

    # total lines
    verbose("Total count logfile lines: %d" % totalLoglineCount)
    script (ddpComment + \
            "Total count logfile lines: %d" % totalLoglineCount)

    # total DDP lines
    verbose("Total count DDP SpW lines: %d  percent DDP SpW lines: %3.2f of total lines" % \
            (totalDDPlineCount, \
            (float(totalDDPlineCount)/float(totalLoglineCount))*100.0))
    script (ddpComment + \
            "Total count DDP SpW lines: %d  percent DDP SpW lines: %3.2f of total lines" % \
            (totalDDPlineCount, \
            (float(totalDDPlineCount)/float(totalLoglineCount))*100.0))

    # total to DDP lines
    verbose("Total count to DDP SpW lines: %d  percent to DDP SpW lines: %3.2f of total DDP lines" % \
            (totalDDPlineToCount, \
            (float(totalDDPlineToCount)/float(totalDDPlineCount))*100.0))
    script (ddpComment + \
            "Total count to DDP SpW lines: %d  percent to DDP SpW lines: %3.2f of total DDP lines" % \
            (totalDDPlineCount, \
            (float(totalDDPlineToCount)/float(totalDDPlineCount))*100.0))

    # total to write command DDP lines
    verbose("Total count to write command DDP SpW lines: %d  percent to write command DDP SpW lines: %3.2f of total DDP to lines" % \
            (totalDDPlineWcCount, \
            (float(totalDDPlineWcCount)/float(totalDDPlineToCount))*100.0))
    script (ddpComment + \
            "Total count to write command DDP SpW lines: %d  percent to write command DDP SpW lines: %3.2f of total DDP to lines" % \
            (totalDDPlineWcCount, \
            (float(totalDDPlineWcCount)/float(totalDDPlineToCount))*100.0))

    # total to write reply DDP lines
    verbose("Total count to write reply DDP SpW lines: %d  percent to write reply DDP SpW lines: %3.2f of total DDP to lines" % \
            (totalDDPlineWrCount, \
            (float(totalDDPlineWrCount)/float(totalDDPlineToCount))*100.0))
    script (ddpComment + \
            "Total count to write reply DDP SpW lines: %d  percent to write reply DDP SpW lines: %3.2f of total DDP to lines" % \
            (totalDDPlineWrCount, \
            (float(totalDDPlineWrCount)/float(totalDDPlineToCount))*100.0))



    # total from DDP lines
    verbose("Total count from DDP SpW lines: %d  percent from DDP SpW lines: %3.2f of total DDP lines" % \
            (totalDDPlineFromCount, \
            (float(totalDDPlineFromCount)/float(totalDDPlineCount))*100.0))
    script (ddpComment + \
            "Total count from DDP SpW lines: %d  percent from DDP SpW lines: %3.2f of total DDP lines" % \
            (totalDDPlineCount, \
            (float(totalDDPlineFromCount)/float(totalDDPlineCount))*100.0))


    verbose("Total count memory dump sequences: %d  total starts: %d  total ends: %d" % \
            (totalMemDumpSeqCount, totalMemDumpStrCount, totalMemDumpEndCount))
    script (ddpComment + \
            "Total count memory dump sequences: %d  total starts: %d  total ends: %d" % \
            (totalMemDumpSeqCount, totalMemDumpStrCount, totalMemDumpEndCount))

    verbose("Total count TOD_PULSE lines checked for 5Hz +/- 1ms: %d" % totalTODPulselineCount)
    script (ddpComment + 
            "Total count TOD_PULSE lines checked for 5Hz +/- 1ms: %d" % totalTODPulselineCount)

    verbose("End time: " + str(datetime.datetime.now()))
    script (ddpComment + \
            "End time: " + str(datetime.datetime.now()))

def calculateLogfileTS(row, headerDict):
    return (float(row[headerDict['Hour']]) * 60.0 * 60.0) + \
           (float(row[headerDict['Min']])  * 60.0) + \
           (float(row[headerDict['Sec']])  * 1.0)
    
def processTODPulseLine(rowNum, fileNum, row,headerDict):
    global totalTODPulselineCount  # this function only deals with TOD_PULSElines
    global previousTODTs

    #debug(str(row))
    # check for a TOD_PULSE line
    if (row[headerDict['Type']] == 'TOD_PULSE'):

       totalTODPulselineCount   += 1  # we found a TOD_Pulse line

       # calculate timestamp of this to DDP SpW command
       ts = calculateLogfileTS(row, csvHeaderDict)
    
       if previousTODTs < 0.0:
          previousTODTs = ts    # one time seedng of timestamps
    
       deltaTs = ts - previousTODTs  # seconds between TOD_PULSE commands
    
       previousTODTs = ts   # this one becomes the previous one for next time
    
       # check for 5Hz delta timing
       if ((deltaTs > 0.0) and \
           ((deltaTs < (0.20 - 0.001)) or \
            (deltaTs > (0.20 + 0.001)))):
          error("File %d Line %d TS %f deltaTs: %f Found %s row: %s" % \
                (fileNum, rowNum, ts, deltaTs, 'TOD_PULSE', str(row))) 
    else:
        pass  # not a TOD line
    
def processSpWFromLine(header, data, ts):
    global ddpComment
    global inMemDumpState
    global memDumpStartTs
    global totalMemDumpEndCount

    # process data first
    data   = data[0:-2]   # slice off " xx$" checksum chars

    p = re.compile('_')
    data = p.sub('', data)   # eliminate _

    # check for memory dump command to dpp
    if ((data[0:8] == '4D444D53') and \
        (inMemDumpState)):     # found a memory dump end command
        inMemDumpState = False # indicate we are out of a mem dump sequence
        totalMemDumpEndCount += 1
        deltaTs = ts - memDumpStartTs  # need to wait this long to allow mem dump sequence to complete
        debug("start ts %f  end ts %f  deltats %f" % (memDumpStartTs,ts,deltaTs))
        debug('end mem dump ' + header + ' ' + data)

        script(ddpComment + \
               "Memory dump start ts: %f  end ts: %f  deltaTs: %f" % \
               (memDumpStartTs, ts, deltaTs))
        script("sleep %d" % int((deltaTs * 1000.0)))
        script(ddpComment + "End of memory dump sequence")
        script("displaylog on")

    else:
        pass  # just a normal from ddp command to do nothing with

def processSpWToLine(header, data, ts, waitTime):

    # process header hex string to determine if SpW reply or command

    # header line is either a 5.3.2 write reply format or 5.3.1 write command format
    # F0012C008000097A                      # 5.3.2 write reply example
    # F00174BF80DC6900F0005000000008B0      # 5.3.1 write command example
    # F001 2C 008000097A                    # 5.3.2 write reply example
    # F001 74 BF80DC6900F0005000000008B0    # 5.3.1 write command example
    # .... ..
    # (....)(?P<ins>..)

    p = re.compile(r"""
                    (....)              # target logical address + pi
                    (?P<ins>..)         # instruction
                    """, re.VERBOSE)    # easy to read header parse re

    m = p.search(header)  # apply re to header to get SpW command part

    # decode instruction byte
    if int(m.group('ins')[0]) > 3:    # bit 6 asserted
        emitScriptRmapCommand(header, data, ts, waitTime)
    else:
        emitScriptRmapReply(header)


def emitScriptRmapReply(header):
    global totalDDPlineWrCount

    script ("# " + "This rmap write reply should be automatically sent by the SpW test equipment")
    totalDDPlineWrCount += 1

def emitScriptRmapCommand(header, data, ts, waitTime):
    global totalDDPlineWcCount
    global inMemDumpState
    global memDumpStartTs  
    global totalMemDumpSeqCount
    global totalMemDumpStrCount

    # process data first
    data   = data[0:-2]   # slice off " xx$" checksum chars

    p = re.compile('_')
    data = p.sub('', data)   # eliminate _

    # check for memory dump command to dpp
    if data[0:8] == '4D444D53':  # found a memory dump start command
        inMemDumpState = True    # indicate we are in a mem dump sequence
        memDumpStartTs = ts      # need to know this for delta time to wait
        totalMemDumpSeqCount += 1  # how many memory dump sequences processed
        totalMemDumpStrCount += 1  # how many memory dump start commands processed
        displayCmd = ddpComment + "Start of memory dump sequence\n" + 'displaylog off'
        debug("start mem dump " + header + ' ' + data + ' ' + displayCmd)
    else:
        displayCmd = ''  # not a mem dump  dont need displayoff

    # process header hex string

    # development of header parser regular expression
    # 0         1         2         3
    # 01234567890123456789012345678901
    # F00174BF80DC6900F0005000000008B0          # 5.3.1 Write Command format
    # 0              1           2           3
    # 01 23 45 67 89 0123 45 67890123 456789 01
    # F0 01 74 BF 80 DC69 00 F0005000 000008 B0
    # .. .. .. .. .. .... .. ........ ...... ..
    # form python named groups
    # (?P<tla>..)(?P<pi>..)(?P<ins>..)(?P<key>..)(?P<ila>..)(?P<tid>....)(?P<ea>..)(?P<addr>........)(?P<len>......)(?P<crc>..)
    #p = re.compile(r'(?P<tla>..)(?P<pi>..)(?P<ins>..)(?P<key>..)(?P<ila>..)(?P<tid>....)(?P<ea>..)(?P<addr>........)(?P<len>......)(?P<crc>..)')

    p = re.compile(r"""
                    (?P<tla>..)         # target logical address
                    (?P<pi>..)          # protocol id
                    (?P<ins>..)         # instruction
                    (?P<key>..)         # key
                    (?P<ila>..)         # initiator logical address
                    (?P<tid>....)       # transaction id
                    (?P<ea>..)          # external address
                    (?P<addr>........)  # address
                    (?P<len>......)     # data length
                    (?P<crc>..)         # header crc
                    """, re.VERBOSE)    # easy to read header parse re

    m = p.search(header)  # apply re to header to get SpW command part

    # decode instruction byte
    rw = 'w' if int(m.group('ins')[0]) > 5 else 'r'    # bit 5 asserted
    vn = 'v' if int(m.group('ins')[0]) % 2 else 'nv'   # bit 4 asserted

    p  = re.compile('[89ABCDEF]')
    rn = 'r' if p.match(m.group('ins')[1]) else 'nr'   # bit 3 asserted

    p  = re.compile('[4567CDEF]')
    ni = 'i' if p.match(m.group('ins')[1]) else 'ni'   # bit 2 asserted

    data = data if rw == 'w' else m.group('len')  # data or data len
    
    totalDDPlineWcCount += 1

    # E M I T  S P W  R M A P  S C R I P T  C O M M A N D S
    #displaylog off         # only if starting a memory dump
    #sleep waitTime(ms)
    #rmap tla r|w v|nv r|nr i|ni sla tid addr data
    #waitresp tid timeout(ms) s|c

    debug (displayCmd)
    script(displayCmd)

    debug ("sleep %d" % int((waitTime * 1000.0)))
    #script("")
    #script(ddpComment +  "wait for delta time %f sec" % waitTime)
    script("sleep %d" % int((waitTime * 1000.0)))
    debug ("rmap %s %s %s %s %s %s %s %s %s" % \
           (m.group('tla'),   \
            rw,               \
            vn,               \
            rn,               \
            ni,               \
            m.group('ila'),   \
            m.group('tid'),   \
            m.group('addr'),  \
            data))
    script("rmap %s %s %s %s %s %s %s %s %s" % \
           (m.group('tla'),   \
            rw,               \
            vn,               \
            rn,               \
            ni,               \
            m.group('ila'),   \
            m.group('tid'),   \
            m.group('addr'),  \
            data))
    debug ("waitrep %s 500 s" % \
           (m.group('tid')))
    script("waitrep %s 500 s" % \
           (m.group('tid')))

def processDDPLine(rowNum, fileNum, row, skipRange, headerDict):
    global ddpToAddress       # this is how we know it is a ddp SpW line
    global ddpFromAddress     # this is how we know it is a ddp SpW line
    global totalDDPlineCount  # this function only deals with ddp SpW lines
    global totalDDPlineToCount
    global totalDDPlineFromCount
    global previousDDPToTs

    # skip lines outside of interest range
    if ((fileNum == 1 and rowNum < skipRange[fileNum-1]) or \
        (fileNum == 2 and rowNum > skipRange[fileNum-1])):  # skipping

        #debug(str(row))
        # T O -> D D P  check for a to DDP SpW command
        if ((row[headerDict['To']]    ==   toDDPAddress) and \
             (row[headerDict['From']] == fromDDPAddress)):

            totalDDPlineCount   += 1  # we found a ddp SpW line
            totalDDPlineToCount += 1  # we found a to ddp SpW line

            # calculate timestamp of this to DDP SpW command
            ts = calculateLogfileTS(row, csvHeaderDict)
    
            if previousDDPToTs < 0.0:
               previousDDPToTs = ts    # one time seedng of timestamps
    
            deltaTs = ts - previousDDPToTs  # seconds between SpW Commands
    
            previousDDPToTs = ts   # this one becomes the previous one for next time
    
            #script("previousDDPToTs: %f  ts: %f  deltaTs: %f" % (previousDDPToTs, ts, deltaTs))
    
            debug ("File %d Line %d TS %f deltaTS %f Found %s ddp row: %s" % \
                   (fileNum, rowNum, ts, deltaTs, 'to', str(row))) 
            script("")
            script(ddpComment + \
                   "%f File %d Line %d TS %f deltaTS %f Found %s ddp row: %s" % \
                   (ts, fileNum, rowNum, ts, deltaTs, 'to', str(row))) 

            # process logfile spw to ddp line (command or reply)
            processSpWToLine(row[headerDict['Header']], \
                             row[headerDict['Data']],   \
                             ts, \
  # need to ts of this command if mem dump start
                             deltaTs)  # need to know delta time to wait before issuing this command
    
        # F R O M <- D D P  check for a from DDP SpW command/message
        elif ((row[headerDict['To']]    == fromDDPAddress) and \
               (row[headerDict['From']] ==   toDDPAddress)):
    
            totalDDPlineCount     += 1  # we found a ddp SpW line
            totalDDPlineFromCount += 1  # we found a from ddp SpW line

            # calculate timestamp of this from DDP SpW command
            ts = calculateLogfileTS(row, csvHeaderDict)

            debug ("File %d Line %d TS %f Found %s ddp row: %s" % \
                   (fileNum, rowNum, ts, 'from', str(row))) 
            script("")
            script(ddpComment + \
                   "%f File %d Line %d TS %f  Found %s ddp row: %s" % \
                   (ts, fileNum, rowNum, ts, 'from', str(row))) 

            # process logfile spw from ddp line (command or reply)
            processSpWFromLine(row[headerDict['Header']], \
                               row[headerDict['Data']],   \
                               ts)    # need to ts of this command if mem dump end
    
        else:
            pass  # not a ddp line

    else:
        pass # out of range


# M A I N  F U N C T I O N
def main():
    global VERSION
    global scriptOutFile
    global ddpComment
    global toDDPAddress
    global fromDDPAddress
    global csvHeaderDict
    global fileSkipRange


    # P R O C E S S  C O M M A N D  L I N E  A R G U M E N T S
    opts, args = processCommandLine()


    # D I S P L A Y  P R E A M B L E
    displayPreamble()


    # O P E N  O U T P U T  F I L E
    scriptOutFile = openOutputFile(args[0])


    # O U T P U T  S C R I P T  F I L E  H E A D E R
    verbose("Generating script file: " + args[0])
    script(ddpComment + VERSION)
    script(ddpComment + "Current time: " + str(datetime.datetime.now()))
    script(ddpComment + "Script file:  " + args[0])
    verbose("Using to   DDP logical address %s" % (toDDPAddress))
    verbose("Using from DDP logical address %s" % (fromDDPAddress))


    # L O O P  I N P U T  F I L E S
    csvFilenames = args[1:]  # obtain list of csv filenames from command line
    fileNum = 0              # which file we are processing

    debug("Processing files: " + str(csvFilenames))
    for csvFilename in csvFilenames:
        fileNum += 1
        script(ddpComment + \
               "Input file #%d csvfilename: %s  skipping from/to line %d" % \
               (fileNum, csvFilename, fileSkipRange[fileNum-1]))
        verbose("Input file #%d csvfilename: %s  skipping from/to line %d" % \
               (fileNum, csvFilename, fileSkipRange[fileNum-1]))

    verbose("Start of reading input files")

    fileNum = 0              # which file we are processing
    for csvFilename in csvFilenames:
        fileNum += 1

    
        # O P E N  I N P U T  F I L E
        csvInFile = openInputFile(csvFilename)


        # O U T P U T  I N P U T  F I L E N A M E  T O  S C R I P T
        verbose("Reading csv file: " + csvFilename)
        script (ddpComment + \
                "Reading file #%d csvfilename: %s  skipping from/to line %d" % \
                (fileNum, csvFilename, fileSkipRange[fileNum-1]))
        debug  ("Reading input file #%d csvfilename: %s  skipping from/to line %d" % \
               (fileNum, csvFilename, fileSkipRange[fileNum-1]))
    

        # L O O P  L O G F I L E  L I N E S
        rows = generate_rows(csvInFile)    # create logfile row generator

        for rowNum, row in enumerate(rows):     # loop for each logfile line

            rowNum += 1   # computer start counting at zero (not line zero but line 1)
            # P R O C E S S  L O G F I L E  L I N E S
            # process for ddp SpW command logfile line
            processDDPLine(rowNum, fileNum, row, fileSkipRange, csvHeaderDict)

            # process TOD_PULSE logfile line
            processTODPulseLine(rowNum, fileNum, row, csvHeaderDict)


        # C L O S E  I N P U T  F I L E
        closeFile(csvInFile, csvFilename)

    verbose("End of reading input files")

    # C L O S E  O U T P U T  F I L E
    closeFile(scriptOutFile, args[0])

    # D I S P L A Y  P O S T A M B L E
    displayPostamble()

# M A I N  S T A R T
if __name__ == "__main__":
    main()
