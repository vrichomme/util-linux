import sys
import os
import re
import glob

from xml.etree import ElementTree

def listVSProj(rootdir: str):
    paths = []

    excludes = ['ALL_BUILD', 'ZERO_CHECK', 'CMakeFiles']
    rootdir = rootdir.replace('\\', '/')
    path = '{}/**/*.vcxproj'.format(rootdir)
    for filename in glob.iglob(path, recursive=True):
        relfname = filename[len(rootdir)+1:]
        
        excl_found = False
        for exclword in excludes:
            if exclword in relfname:
                excl_found = True
                break
        if not excl_found:
            paths.append(filename)

    return paths


def getNamespace(element):
    m = re.match('\{.*\}', element.tag)
    return m.group(0) if m else ''

def fixVSProj(filepath):

    xDoc = ElementTree.parse(filepath)
    xRoot = xDoc.getroot()
    ns = getNamespace(xRoot)

    #<ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='RelWithDebInfo|Win32'">
    e = xDoc.findall('{0}Items/{0}Item/{0}ItemAttributes/{0}ListPrice/{0}Amount'.format(namespace))
    
    print(xRoot.tag)

    return

def main():
     if len(sys.argv) < 2:
         sys.exit(-1)

     rootdir = os.path.abspath(sys.argv[1])
     
     vsprojs = listVSProj(rootdir)
     for vsproj in vsprojs:
         fixVSProj(vsproj)


if __name__ == "__main__":
    main()
