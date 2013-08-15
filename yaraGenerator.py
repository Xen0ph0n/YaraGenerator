#! /usr/bin/python
# YaraGenerator Will Automatically Build Yara Rules For Malware Families
# As of Yet this Only Works Well With Executables
# Copyright 2013 Chris Clark chris@xenosec.org
# Released under GPL3 Licence

import re, sys, os, argparse, hashlib, random
from datetime import datetime

#Ensure Import path is in syspath
pathname = os.path.abspath(os.path.dirname(sys.argv[0]))
sys.path.append(pathname + '/modules')


#Make sure requred imports are present
try:
  import pefile
except:
  print "[!] PEfile not installed or present in ./modules directory"
  sys.exit(1) 

def getFiles(workingdir):
  global hashList
  fileDict = {}
  hashList = [] 
  #get hashes
  for f in os.listdir(workingdir):
    if os.path.isfile(workingdir + f) and not f.startswith("."):
     fhash = md5sum(workingdir + f)
     fileDict[fhash] = workingdir + f
     hashList.append(fhash)
  if len(fileDict) == 0:
    print "[!] No Files Present in \"" + workingdir +"\"" 
    sys.exit(1) 
  else: 
    return fileDict


#Use PEfile for executables and remove import/api calls from sigs
def exeImportsFuncs(filename, allstrings):
    try:
        pe = pefile.PE(filename)
        importlist = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT: 
          importlist.append(entry.dll)
          for imp in entry.imports:
            importlist.append(imp.name)
        for imp in importlist:
          if imp in allstrings: allstrings.remove(imp)
        if len(allstrings) > 0:
          return list(set(allstrings))
        else:
          print '[!] No Extractable Attributes Present in Hash: '+str(md5sum(filename)) + 'Please Remove it from the Sample Set and Try Again!'
          sys.exit(1) 
    except:  
        return allstrings

#Simple String / ASCII Wide string extraction 
def getStrings(filename):
  try:
    data = open(filename,'rb').read()
    chars = r"A-Za-z0-9/\-:.,_$%@'()\\\{\};\]\[<> "
    regexp = '[%s]{%d,100}' % (chars, 6)
    pattern = re.compile(regexp)
    strlist = pattern.findall(data)
    #Get Wide Strings
    unicode_str = re.compile( ur'(?:[\x20-\x7E][\x00]){6,100}',re.UNICODE ) 
    unicodelist = unicode_str.findall(data) 
    allstrings = unicodelist + strlist
    # use pefile to extract names of imports and function calls and remove them from string list
    if len(allstrings) > 0:
        return list(set(allstrings))
    else:
      print '[!] No Extractable Attributes Present in Hash: '+str(md5sum(filename)) + 'Please Remove it from the Sample Set and Try Again!'
      sys.exit(1) 
  except Exception:
    print '[!] No Extractable Attributes Present in Hash: '+str(md5sum(filename)) + 'Please Remove it from the Sample Set and Try Again!'
    sys.exit(1)

def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest() 


#find common strings and check against filetype specific blacklists
def findCommonStrings(fileDict, filetype):
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

  #import and use filetype specific blacklist/regexlist to exclude unwanted sig material
  #Various utility functions to extract strings/data/info and isolate signature material
  with open('modules/'+filetype+'_blacklist.txt') as f:
    blacklist = f.read().splitlines()
  with open('modules/'+filetype+'_regexblacklist.txt') as f:
    regblacklist = f.read().splitlines()
  #Match Against Blacklist
  for black in blacklist:
    if black in finalStringList: finalStringList.remove(black)
  #Match Against Regex Blacklist
  regmatchlist = []
  for regblack in regblacklist:
    for string in finalStringList:
      regex = re.compile(regblack) 
      if regex.search(string): regmatchlist.append(string)
  if len(regmatchlist) > 0:
    for match in list(set(regmatchlist)):
      finalStringList.remove(match)

  return finalStringList

#Build the actual rule
def buildYara(options, strings, hashes):
  date = datetime.now().strftime("%Y-%m-%d")
  randStrings = []
  try:
    for i in range(1,20):
  	 randStrings.append(random.choice(strings))
  except IndexError:
    print '[!] No Common Attributes Found For All Samples, Please Be More Selective'
    sys.exit(1)

  randStrings = list(set(randStrings))

  ruleOutFile = open(options.RuleName + ".yar", "w")
  ruleOutFile.write("rule "+options.RuleName)
  if options.Tags:
    ruleOutFile.write(" : " + options.Tags)
  ruleOutFile.write("\n")
  ruleOutFile.write("{\n")
  ruleOutFile.write("meta:\n")
  ruleOutFile.write("\tauthor = \""+ options.Author + "\"\n")
  ruleOutFile.write("\tdate = \""+ date +"\"\n")
  ruleOutFile.write("\tdescription = \""+ options.Description + "\"\n")
  for h in hashes:
  	ruleOutFile.write("\thash"+str(hashes.index(h))+" = \""+ h + "\"\n")
  ruleOutFile.write("\tsample_filetype = \""+ options.FileType + "\"\n")
  ruleOutFile.write("\tyaragenerator = \"https://github.com/Xen0ph0n/YaraGenerator\"\n")
  ruleOutFile.write("strings:\n")
  for s in randStrings:
    if "\x00" in s:
      ruleOutFile.write("\t$string"+str(randStrings.index(s))+" = \""+ s.replace("\\","\\\\").replace('"','\\"').replace("\x00","") +"\" wide\n")
    else:  
      ruleOutFile.write("\t$string"+str(randStrings.index(s))+" = \""+ s.replace("\\","\\\\") +"\"\n")
  ruleOutFile.write("condition:\n")
  ruleOutFile.write("\t"+str(len(randStrings) - 1)+" of them\n")
  ruleOutFile.write("}\n")
  ruleOutFile.close()
  return

#Per filetype execution paths
def unknownFile(fileDict):
  #Unknown is the default and will mirror executable excepting the blacklist
  for fhash, path in fileDict.iteritems():
    fileDict[fhash] = getStrings(path)
  finalStringList = findCommonStrings(fileDict, 'unknown')
  return finalStringList

def exeFile(fileDict):
  for fhash, path in fileDict.iteritems():
    fileDict[fhash] = exeImportsFuncs(path, getStrings(path))
  finalStringList = findCommonStrings(fileDict, 'exe')
  return finalStringList

def pdfFile(fileDict):
  for fhash, path in fileDict.iteritems():
    fileDict[fhash] = getStrings(path)
  finalStringList = findCommonStrings(fileDict, 'pdf')
  return finalStringList

def emailFile(fileDict):
  for fhash, path in fileDict.iteritems():
    fileDict[fhash] = getStrings(path)
  finalStringList = findCommonStrings(fileDict, 'email')
  return finalStringList

def officeFile(fileDict):
  for fhash, path in fileDict.iteritems():
    fileDict[fhash] = getStrings(path)
  finalStringList = findCommonStrings(fileDict, 'office')
  return finalStringList

def jshtmlFile(fileDict):
  for fhash, path in fileDict.iteritems():
    fileDict[fhash] = getStrings(path)
  finalStringList = findCommonStrings(fileDict, 'jshtml')
  return finalStringList

#Main
def main():
  filetypeoptions = ['unknown','exe','pdf','email','office','js-html']
  opt = argparse.ArgumentParser(description="YaraGenerator")
  opt.add_argument("InputDirectory", help="Path To Files To Create Yara Rule From")
  opt.add_argument("-r", "--RuleName", required=True , help="Enter A Rule/Alert Name (No Spaces + Must Start with Letter)")
  opt.add_argument("-a", "--Author", default="Anonymous", help="Enter Author Name")
  opt.add_argument("-d", "--Description",default="No Description Provided",help="Provide a useful description of the Yara Rule")
  opt.add_argument("-t", "--Tags",default="",help="Apply Tags to Yara Rule For Easy Reference (AlphaNumeric)")
  opt.add_argument("-v", "--Verbose",default=False,action="store_true", help= "Print Finished Rule To Standard Out")
  opt.add_argument("-f", "--FileType", required=True, default='unknown',choices=filetypeoptions, help= "Select Sample Set FileType choices are: "+', '.join(filetypeoptions), metavar="")
  if len(sys.argv)<=3:
    opt.print_help()
    sys.exit(1)
  options = opt.parse_args()
  if " " in options.RuleName or not options.RuleName[0].isalpha():
  	print "[!] Rule Name Can Not Contain Spaces or Begin With A Non Alpha Character"


  #Get Filenames and hashes
  fileDict = getFiles(options.InputDirectory)
  print "\n[+] Generating Yara Rule " + options.RuleName + " from files located in: " + options.InputDirectory
  
  #Begin per-filetype processing paths
  if options.FileType == 'exe':
    finalStringList = exeFile(fileDict)
  elif options.FileType == 'pdf':
    finalStringList = pdfFile(fileDict)
  elif options.FileType == 'email':
    finalStringList = emailFile(fileDict)
  elif options.FileType == 'office':
    finalStringList = officeFile(fileDict)
  elif options.FileType == 'js-html':
    finalStringList = jshtmlFile(fileDict)
  else:
    finalStringList = unknownFile(fileDict)

  #Build and Write Yara Rule
  global hashList
  buildYara(options, finalStringList, hashList)
  print "\n[+] Yara Rule Generated: "+options.RuleName+".yar\n"
  print "  [+] Files Examined: " + str(hashList)
  print "  [+] Author Credited: " + options.Author
  print "  [+] Rule Description: " + options.Description 
  if options.Tags:
    print "  [+] Rule Tags: " + options.Tags +"\n"
  if options.Verbose:
    print "[+] Rule Below:\n"
    with open(options.RuleName + ".yar", 'r') as donerule:
      print donerule.read()

  print "[+] YaraGenerator (C) 2013 Chris@xenosec.org https://github.com/Xen0ph0n/YaraGenerator"


if __name__ == "__main__":	
	main()