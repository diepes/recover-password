#!/usr/bin/env python
import os , random , subprocess, sys, datetime, time
import pexpect
#import timeit
#import numpy # to get zeros #replace with [0] * len
'''Pes modify '''
#from commands import getoutput
lenmin=3
lenmax=5
trys=5000
words = {}  ##Passwords and rules
wordscount = {} ##Count usage of passwords and placement
pwdcount=0 ## Counts Passwd try's
  #PyList_New(len(w)) ##Dict of pwd with list of placement.
  #print words
  ##words.append(w[:-1])  ##Add to list, remove newline
  #print "Word: ",w[:-1]
# command = 'openssl rsa -in mysecuresite.com.key -out tmp.key -passin pass:%s'
#command = '/usr/bin/cryptmount personal'
cryptfile=".cryptofileLUKS"  # used to make sure we have the right loop, match losetup -a
command_pre ='losetup -a'
#losetup --find --show ~/.cryptofileLUKS
command = 'cryptsetup luksOpen /dev/loop%s personal'
fout = open("LOG.TXT","w")
fout.flush()
timestart = datetime.datetime.now()
fout.write( "Started ... %s\n" % (timestart) )

def loadPasswords(fname='secret-words.txt'):
   global words
   global wordscount
   global lenmax
   f = open(fname, 'r')
   ''' Format of secret file
      line with word and then pos allowed or !2 not allowed
      e.g.
      pass 1 2 3 !4 !5
   '''
   words = {}  ##reset to empty
   for line in f:
      w = line.strip().split()
      print "Read:",w,"#",len(w)
      if len(w) > 1:
        words[w[0]] = w[1:]
      elif len(w) > 0:
        words[w[0]] = []
      else:
        continue
      if not w[0] in wordscount: ##Allow for dynamic reload, can not change lenmax
         wordscount[w[0]] = [0] * lenmax #Add another tulip, stats {(1,30),(2,20)}

def preCommands():
    ''' find loop dev, insert dev into command '''
    child = pexpect.spawn(command_pre)
    i = child.expect([pexpect.TIMEOUT, 'password', 'warning:', 'ermission', '/dev/loop(/?\d+):.{10,30}(%s).*\)' % (cryptfile)
                                     , pexpect.EOF])
    if i == 0: # match: Timeout
        print '>ERROR!'
        print '>%s said:' %(command_pre)
        print '>',child.before, child.after
        sys.exit (1)
    if i == 1: # match: sudo
	print ">Problem sudo needs password. Try running as root."
	print '>%s said:' %(command_pre)
        print '>',child.before, child.after
        sys.exit(1)
    if i == 2: #   match: warning
	print ">Problem setting up loop, clear all."
	print '>%s said:' %(command_pre)
        print '>',child.before, child.after
        sys.exit(1)
    if i == 3: #  match: warning
	print ">Problem not enough right to setup loop."
	print '>%s said:' %(command_pre)
        print '>',child.before,'>', child.after
        sys.exit(1)
    if i == 4: # found loop dev in child match
        print "Got loop ..i=",i
	print '>%s said:' %(command_pre)
        print '>',child.before,'>', child.after
        print" match loopdev= >>",child.match.groups(),"<<"
        command2 = command % (child.match.group(1))
        print "command=",command2
        return command2
    if i == 5:
        print "Un-expected EOF ...  No loop found for file %s" % (cryptfile)
        print " setup loop # losetup -f %s" % (cryptfile)
        print '>%s said:' %(command_pre)
        print '>',child.before,'>', child.after

        sys.exit(1)

def dumpStats():
    global pwdcount
    global wordscount
    global words
    if not (pwdcount % 100):
       l = "Count =%s  Tdelta=%s\n" % (pwdcount,datetime.datetime.now()-timestart)
       fout.write( l )
       fout.flush()
       print
       print l
    if not (pwdcount % 10): ##dump passwd usage.
       print
       print "Pass min=%s max=%s" % (lenmin, lenmax)
       stat = [0] * (lenmax)
       stattotal = 0
       for w in wordscount:
         print sum(wordscount[w]), wordscount[w] , " >> ", w , "[",words[w],"]"
         stattotal += sum(wordscount[w]) #total of total
         stat = [sum(pair) for pair in zip(stat, wordscount[w])]  #add vertical
       print  stattotal , stat, " << TOTAL (reloading Pass file)"
       loadPasswords() ## Check for new passwd's

def getPassword():
    len_count = random.randint(lenmin,lenmax)
    passwd = [""] * len_count  #Create list.
    for i in xrange(len_count):
      test = 1
      while test > 0: ##loop until rules met >pass 1 !2 3
        test = 1
        w = random.choice(words.keys())
        while w in passwd[:i]: ##prevent duplicate words
           w = random.choice(words.keys())
        passwd[i] = w ##pre assign or over write
        ## if a test matches we leave
        for x in words[w]: #Test for rules
           if x[0] == "!": #not this number
              if int(x[1:]) == i+1:
                 test = 100  #Cant use this pass
              else:
                 test -= 1  # Was not this.
           else:
              if int(x) == i+1:
                 test -= 1
        if len(words[w]) == 0: #no rules, pass
           test -= 1
        #print "w=%s[%s]%s pos=%s/%s passwd=%s" % (w,words[w],len(words[w]),i+1,len_count,passwd)
      wordscount[w][i] += 1
    return "".join(passwd) , len_count

def main():
  global pwdcount
  global command
  dt = False
  t1 = time.time() ##inc time
  tt2 = time.time() ##total time
  loadPasswords()
  #command = preCommands()
  command = "sudo cryptsetup luksOpen /home/pieter/.cryptofileLUKS personal"
  #command = 'sudo echo "Enter passphrase" ; read var ; echo "$var unlocked"'
  print("Command=",command)
  fout.write( "Start password try's ... Delta %s\n" % (datetime.datetime.now()-timestart) )
  fout.flush()

  while pwdcount < trys:
    child = pexpect.spawn(command)
    print("run command = ",command)
    t2 = time.time() #initialize, updated later
    if dt: print "tspawn=%s" % (t2-t1), ; t1=t2
    i = 1 #Enter pass
    while i == 1:
      i = child.expect([pexpect.TIMEOUT
                        ,'Enter passphrase' #i=1
                        ,"password for" #i=2 [sudo] password for
                        ,'No key available with this passphrase.'
                        ,'unlocked' #i=4
                        ])
      #                                                      No key available with this passphrase.
      print "go",i,pwdcount
      t2 = time.time()
      if dt: print "texp=%s" % (t2-t1), ; t1=t2
      if i == 0: # Timeout
         print 'ERROR!-Timeout',i
         print '  %s said:' %(command)
         print "  debug:",child.before,"<=>", child.after
         sys.exit (1)
      if i == 1: # Asking for passphrase
         passX, passlen = getPassword()
         t2 = time.time()
         if dt: print "tpask=%s -%s-" % (t2-t1,passX), ; t1=t2
         child.sendline ( passX )
         t2 = time.time()
         if dt: print "tpsend=%s" % (t2-t1), ; t1=t2
         pwdcount += 1
         tt1 = time.time()
         tt2 = tt1-tt2
         print
         print "Pass %5d  tt2=%f  p=%s" \
			           % (pwdcount,tt2, passX), passlen ,
         tt2 = tt1
         #print "                              ." ,
         sys.stdout.flush()

         #print("dumpStats()")
         dumpStats()

      if i == 2: #[sudo]
         print "Error, need sudo password."
         print "  debug:",child.before,"<=>", child.after
         exit(1)

      if i > 3: #timeout or unlocked
           print 'GOT IT!', passX
           fout.write( "Pass: %s\n" % (passX) )
           #break
           fout.close()
           sys.exit(1)

if __name__ == '__main__':
    main()

