import os , random , subprocess
import pexpect
import sys
'''Pes modify '''
#from commands import getoutput

f = open('secret-words.txt', 'r')
# words = []
# for w in f:
#  words.append(w[:-1])  ##Add to list, remove newline
#  print( "Word: ",w[:-1] )

lenmin=3
lenmax=5   
trys=3000000
# command = 'openssl rsa -in mysecuresite.com.key -out tmp.key -passin pass:%s'
command = '/usr/bin/cryptmount personal'
#command = '/usr/bin/cryptmount crypttest'
passwdMaxLen = 5 #Words
fout = open("LOG.TXT","w")
fout.write( "Started ... " )

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

def main():
  loadPasswords()
  for num in range(trys):
    len_count = random.randint(lenmin,lenmax)
    passX = ''.join([random.choice(words[i]) for i in range(len_count)])
    child = pexpect.spawn(command)
    #fout = file ("LOG.TXT","wb")
    #child.setlog (fout)	
    i = child.expect([pexpect.TIMEOUT, 'Enter password'])
    if i == 0: # Timeout
        print( 'ERROR!' )
        print( '%s said:' %(command) )
        print( child.before, child.after )
        sys.exit (1)
    if i == 1: # Asking for pass
        child.sendline ( passX )
        print(f"Sent password {num}/{trys} passX={passX}" )

    i = child.expect ([pexpect.TIMEOUT, 'Failed to extract cipher key'])
    if i == 0:
        print( 'GOT IT!', passX, "  stdout=", child.before, " ## ", child.after )
        fout.write( "Pass:" + passX )
        fout.close()
        sys.exit(1)
    if i != 1:
        print( 'No luck - error -----------' )
        print( child.before, child.after )
        print(  "AAA", child.before, child.after , "BBB" )

if __name__ == '__main__':
    main()

