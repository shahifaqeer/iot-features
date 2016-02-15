from __future__ import division

import os
import subprocess
import glob

folder_to_ip = {'ipcam':'10.42.0.44',
                'ubi':'10.0.0.7',
                'dos_simulation':'10.0.0.40',
                'nest':'10.0.0.5',
                'normal_pc_usage':'10.8.113.202',
                'photoframe':'192.168.71.103',
                'photoframe2':'10.42.0.22',
                'smartthings':'10.42.0.89'}


def fix_files_in_folder(folder):
    for files in os.listdir("../data/"+folder+"/"):

        if not os.path.exists("../processed/fixed/"+folder):
            os.makedirs("../processed/fixed/"+folder)

        inputfile = "../data/"+folder+"/"+files
        outputfile = "../processed/fixed/"+folder+"/"+files
        #print inputfile, outputfile
        subprocess.call("pcapfix "+inputfile+" -o "+outputfile, shell=True)
    return

def filter_files_in_folder(folder):
    for files in os.listdir("../processed/fixed/"+folder+"/"):

        if not os.path.exists("../processed/filtered/"+folder):
            os.makedirs("../processed/filtered/"+folder)

        inputfile = "../processed/fixed/"+folder+"/"+files
        outputfile = "../processed/filtered/"+folder+"/"+files.split('.')[0]+".pcap"
        filter_ip = "ip.addr=="+folder_to_ip[folder]
        print inputfile, outputfile, filter_ip
        subprocess.call("tshark -r "+inputfile+" -R '"+filter_ip+"' -w "+outputfile, shell=True)
    return

def bro_files_in_folder(folder):
    for files in os.listdir("../processed/filtered/"+folder+"/"):

        inputfile = "../processed/filtered/"+folder+"/"+files
        outputfolder = "../processed/bro_log/"+folder+"/"+files.split('.')[0]
        if not os.path.exists(outputfolder):
            os.makedirs(outputfolder)
        print inputfile, outputfolder
        subprocess.call("cp "+inputfile+" "+outputfolder+"/", shell=True)
        subprocess.Popen(["bro", "-r", files], cwd=outputfolder)
    return


if __name__=="__main__":
    #INPUTFOLDER = "../data/"
    #INPUTFOLDER = "../processed/fixed/"
    INPUTFOLDER = "../processed/filtered/"
    for folders in os.listdir(INPUTFOLDER):
        print folders
        #fix_files_in_folder(folders)
        #filter_files_in_folder(folders)
        bro_files_in_folder(folders)
