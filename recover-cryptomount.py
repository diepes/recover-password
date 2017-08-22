import os , random , subprocess
import pexpect
'''Pes modify '''
#from commands import getoutput

f = open('secret-words.txt', 'r')
words = []
for w in f:
 words.append(w[:-1])  ##Add to list, remove newline
 print "Word: ",w[:-1]
lenmin=3
lenmax=5   
trys=3000000
# command = 'openssl rsa -in mysecuresite.com.key -out tmp.key -passin pass:%s'
#command = '/usr/bin/cryptmount personal'
command = '/usr/bin/cryptmount crypttest'
passwdMaxLen = 5 #Words
fout = open("LOG.TXT","w")
fout.write( "Started ... " )
def main():
  for num in range(trys):
    len_count = random.randint(lenmin,lenmax)
    passX = ''.join([random.choice(words) for i in xrange(len_count)])
    child = pexpect.spawn(command)
    #fout = file ("LOG.TXT","wb")
    #child.setlog (fout)	
    i = child.expect([pexpect.TIMEOUT, 'Enter password'])
    if i == 0: # Timeout
        print 'ERROR!'
        print '%s said:' %(command)
        print child.before, child.after
        sys.exit (1)
    if i == 1: # Asking for pass
	child.sendline ( passX )
	print "Sent password %s/%s"%(num,trys), passX

    i = child.expect ([pexpect.TIMEOUT, 'Failed to extract cipher key'])
    if i == 0:
        print 'GOT IT!', passX, "  stdout=", out
	fout.write( "Pass:" + passX )
	fout.close()
        sys.exit(1)
    if i <> 1:
        print 'No luck - error -----------'
	print child.before, child.after
    print  "AAA", child.before, child.after , "BBB"

if __name__ == '__main__':
    main()

