#!/usr/bin/env python3
import os , random , subprocess, sys, datetime, time
import pexpect

'''Pes modify uncomment required decryption '''
## COMMANDS 1 openssl encrypted
# command = 'openssl rsa -in mysecuresite.com.key -out tmp.key -passin pass:%s'

## COMM
command = '/usr/bin/cryptmount personal'
cryptfile=".cryptofileLUKS"  # used to make sure we have the right loop, match losetup -a
#command_pre ='losetup -a'
#losetup --find --show ~/.cryptofileLUKS
#command = 'cryptsetup luksOpen /dev/loop%s personal'

    #command = preCommands()

    # command = "sudo /sbin/cryptsetup -v luksOpen ~/.cryptofileLUKS personal"
    # command = "/usr/bin/ssh-keygen -p -f id_rsa.new"
    # command = "/usr/bin/ssh-keygen -p -f id_rsa_aws1"

    #command = 'sudo echo "Enter passphrase" ; read var ; echo "$var unlocked"'
lenmin=3
lenmax=5
trys=500000
words = {}  ##Passwords and rules
wordscount = {} ##Count usage of passwords and placement
pwdcount=0 ## Counts Passwd try's
    #PyList_New(len(w)) ##Dict of pwd with list of placement.
    #print( words )
    ##words.append(w[:-1])  ##Add to list, remove newline
    #print( "Word: ",w[:-1] )
fout = open("LOG.TXT","w")
fout.flush()
timestart = datetime.datetime.now()
fout.write( f"Started ... {timestart}\n" )
def main(**kwargs):
    run(**kwargs)

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
        print( f"Read: {w} #{len(w)}" )
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
    i = child.expect([pexpect.TIMEOUT
                     ,'password'
                     ,'warning:'
                     ,'ermission'
                     ,'/dev/loop(/?\d+):.{10,30}(%s).*\)' % (cryptfile)
                     , pexpect.EOF])
    if i == 0: # match: Timeout
        print( '>ERROR!' )
        print( f'>{command_pre} said:' )
        print( f'> {child.before} {child.after}' )
        sys.exit (1)
    if i == 1: # match: sudo
        print( f'>{command_pre} said:' )
        print( f'> {child.before} {child.after}' )
        sys.exit(1)
    if i == 2: #   match: warning
        print( ">Problem setting up loop, clear all." )
        print( f'>{command_pre} said:' )
        print( f'> {child.before} {child.after}' )
        sys.exit(1)
    if i == 3: #  match: warning
        print( ">Problem not enough right to setup loop." )
        print( f'>{command_pre} said:' )
        print( f'> {child.before} > {child.after}' )
        sys.exit(1)
    if i == 4: # found loop dev in child match
        print( f"Got loop ..i={i}" )
        print( f'>{command_pre} said:' )
        print( f'> {child.before} > {child.after}' )
        print( f" match loopdev= >> {child.match.groups()} <<" )
        command2 = command % (child.match.group(1))
        print( f"command= {command2}" )
        return command2
    if i == 5:
        print( f"Un-expected EOF ...  No loop found for file {cryptfile}" )
        print( f" setup loop # losetup -f {cryptfile}" )
        print( f'>{command_pre} said:' )
        print( f'> {child.before} > {child.after}' )

        sys.exit(1)

def dumpStats():
    global pwdcount
    global wordscount
    global words
    if not (pwdcount % 100):
        l = "Count ={}  Tdelta={}\n".format(pwdcount,datetime.datetime.now()-timestart)
        fout.write( l )
        fout.flush()
        print()
        print( l )
    if not (pwdcount % 100): ##dump passwd usage.
        print()
        print( f"Pass min={lenmin} max={lenmax}" )
        stat = [0] * (lenmax)
        stattotal = 0
        for w in wordscount:
            print( f"{sum(wordscount[w])}, {wordscount[w]}  >>  {w}  [,{words[w]},]" )
            stattotal += sum(wordscount[w]) #total of total
            stat = [sum(pair) for pair in zip(stat, wordscount[w])]  #add vertical
        print(  f"{stattotal} , {stat}  << TOTAL (reloading Pass file)" )

def getPassword():
    len_count = random.randint(lenmin,lenmax)
    passwd = [""] * len_count  #Create list.
    for i in range(len_count):
        test = 1
        count_loop = 0
        while test > 0: ##loop until rules met >pass 1 !2 3
            test = 1
            count_loop += 1
            w = random.choice(list(words.keys()))
            ##prevent duplicate words
            J = 0
            while ( w in passwd[:i] ):
                count_loop += 1
                if count_loop > 1000:
                    print(f"Err: Password loop len_count={len_count} w={w} passwd={passwd}.")
                    sys.exit(1)
                w = random.choice(list(words.keys()))
            passwd[i] = w ##pre assign or over write
            ## if a test matches we leave
            for x in words[w]: #Test for rules
                if x[0] == "!": #not this number
                    if int(x[1:]) == i+1:
                        test = 100  #Cant use this pass
                    else:
                        test -= 1  # Was not this. OK
                else:
                    if int(x) == i+1: 
                        test -= 1
            if len(words[w]) == 0: #no rules, pass
                test -= 1
            #print( "w=%s[%s]%s pos=%s/%s passwd=%s" % (w,words[w],len(words[w]),i+1,len_count,passwd) )
        wordscount[w][i] += 1
    return "".join(passwd) , len_count

def run(**kwargs):
    global pwdcount
    global command
    dt = False  # Debug
    tt2 = time.time() ##total time
    loadPasswords(kwargs['fname'])
    print( f"Command={command}" )
    fout.write( "Start password try's ... Delta {}\n".format(datetime.datetime.now()-timestart) )
    fout.flush()

    while pwdcount < trys:
        t1 = time.time()
        child = pexpect.spawn(command)
        #print( f"run command = {command}" )
        t2 = time.time() #initialize, updated later
        if dt: print( f"tspawn={(t2-t1)}" )
        i = 1 #Enter pass
        while i == 1:  # 1 => Asking for password
            i = child.expect([pexpect.TIMEOUT
                            ,'Enter passphrase|Enter old passphrase:|Enter password for target' #i=1 , cryptsetup|ssh-keyagent
                            ,"[sudo] password for" #i=2 [sudo] password for
                            ,'No key available with this passphrase.|incorrect passphrase supplied to decrypt private key|Failed to extract cipher key'
                            ,'unlocked|e2fsck |Enter new passphrase|clean' #i=4
                            ," already exists"
                            ], timeout=5)
            t3 = time.time()
            #print( f"go i={i} pwdcount={pwdcount}  texp={(t2-t1)}", flush=True )

            if i == 0: # Timeout
                print( f'ERROR!-Timeout {i}' )
                print( f'  {command} said:' )
                print( f"  debug: {child.before} <=> {child.after}" )
                sys.exit (1)
            if i == 1: # Asking for passphrase
                #print( f"debug0", flush=True )
                passX, passlen = getPassword()
                t4 = time.time()
                if dt: print( f"  tpask={t2-t1} -{passX}-" ) ; t1=t2
                #print( f"debug1", flush=True )
                child.sendline( passX )
                #print( f"debug2", flush=True )
                t5 = time.time()
                if dt: print( f"  tpsend={t2-t1}" ) ; t1=t2
                pwdcount += 1
                #print()

                dumpStats()
                loadPasswords(kwargs['fname']) ## Check for new passwd's

            if i == 2: #[sudo]
                print( f"Error, need sudo password." )
                print( f"  debug: {child.before} <=> {child.after}" )
                exit(1)

            if i == 3:
                t6 = time.time()
                print( f"  Pass pwdcount={pwdcount:5d}"
                       f"  tt2={t2-t1:.03f} t3={t3-t2:.03f}"
                       f" t4={t4-t3:.03f} t5={t5-t4:.03f}"
                       f" t6={t6-t5:.03f} tt={t6-t1:.03f}"
                       f" len={passlen} p={passX}" ,
                       flush=True)

            if i == 4: #unlocked
                print( f'GOT IT! {passX}', flush=True )
                fout.write( f"Pass: passX={passX}\n" )
                #break
                fout.close()
                sys.exit(1)

        if i > 4: #Error
            break
    #Error escaped while
    print( f'ERROR! i={i}' )
    print( f'  {command} said:' )
    print( f"  debug: {child.before} <=> {child.after}" )
    sys.exit (1)


if __name__ == '__main__':
    main(fname='secret-words.txt')
