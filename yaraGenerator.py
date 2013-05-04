#! /usr/bin/python
# YaraGenerator Will Automatically Build Yara Rules For Malware Families
# As of Yet this Only Works Well With Executables
# Copyright 2013 Chris Clark chris@xenosec.org
# Released under GPL3 Licence

import re, sys, os, argparse, hashlib, random
from datetime import datetime

def getStrings(filename):
  data = open(filename,'rb').read()
  chars = r"A-Za-z0-9/\-:.,_$%@'()\\\{\};\]\[<> "
  regexp = '[%s]{%d,}' % (chars, 6)
  pattern = re.compile(regexp)
  strlist = pattern.findall(data)
  return list(set(strlist))

def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest() 

def findCommonStrings(fileDict):
  baseStringList = random.choice(fileDict.values())
  finalStringList = []
  matchNumber = len(fileDict)
  for s in baseStringList:
  	sNum = 0
  	for key, value in fileDict.iteritems():
  		if s in value:
  			sNum +=1
  	if sNum == matchNumber:
  		finalStringList.append(s)

  return finalStringList

def buildYara(options, strings, hashes):
  date = datetime.now().strftime("%Y-%m-%d")
  randStrings = []
  for i in range(1,30):
  	randStrings.append(random.choice(strings))
  randStrings = list(set(randStrings))

  ruleOutFile = open(options.RuleName + ".yar", "w")
  ruleOutFile.write("rule "+options.RuleName+"\n")
  ruleOutFile.write("{\n")
  ruleOutFile.write("meta:\n")
  ruleOutFile.write("\tauthor = \""+ options.Author + "\"\n")
  ruleOutFile.write("\tdate = \""+ date +"\"\n")
  ruleOutFile.write("\tdescription = \""+ options.Description + "\"\n")
  for h in hashes:
  	ruleOutFile.write("\thash"+str(hashes.index(h))+" = \""+ h + "\"\n")
  ruleOutFile.write("\tyaragenerator = \"https://github.com/Xen0ph0n/YaraGenerator\"\n")
  ruleOutFile.write("strings:\n")
  for s in randStrings:
  	ruleOutFile.write("\t$string"+str(randStrings.index(s))+" = \""+ s.replace("\\","\\\\") +"\"\n")
  ruleOutFile.write("condition:\n")
  ruleOutFile.write("\tall of them\n")
  ruleOutFile.write("}\n")
  ruleOutFile.close()
  return

def main():
  opt = argparse.ArgumentParser(description="YaraGenerator")
  opt.add_argument("InputDirectory", help="Path To Files To Create Yara Rule From")
  opt.add_argument("-r", "--RuleName", required=True , help="Enter A Rule/Alert Name (No Spaces + Must Start with Letter)")
  opt.add_argument("-a", "--Author", default="Anonymous", help="Enter Author Name")
  opt.add_argument("-d", "--Description",default="No Description Provided",help="Provide a useful description of the Yara Rule")
  if len(sys.argv)<=2:
    opt.print_help()
    sys.exit(1)
  options = opt.parse_args()
  if " " in options.RuleName or not options.RuleName[0].isalpha():
  	print "[-] Rule Name Can Not Contain Spaces or Begin With A Non Alpha Character"
  workingdir = options.InputDirectory
  fileDict = {}
  hashList = []

  #get hashes and strings 
  for f in os.listdir(workingdir):
  	fhash = md5sum(workingdir + f)
  	fileDict[fhash] = getStrings(workingdir + f)
  	hashList.append(fhash)
  
  #Isolate strings present in all files
  finalStringList = findCommonStrings(fileDict)


  #Build and Write Yara Rule
  buildYara(options, finalStringList, hashList)
  print "\n[+] Yara Rule Generated: "+options.RuleName+".yar\n"
  print "  [+] Files Examined: " + str(hashList)
  print "  [+] Author Credited: " + options.Author
  print "  [+] Rule Description: " + options.Description 
  print "\n[+] YaraGenerator (C) 2013 Chris@xenosec.org https://github.com/Xen0ph0n/YaraGenerator"


if __name__ == "__main__":	
	main()