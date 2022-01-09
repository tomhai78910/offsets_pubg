# Author: Tien  (Inspired on Uwric and by eb's Offsets.py)
# Version:  Based on version 1.4 current 9.20

# Imports
from idc import BADADDR, INF_BASEADDR, SEARCH_DOWN, FUNCATTR_START, FUNCATTR_END
import idc
import idaapi
import idautils
import datetime

# Settings
definePrefix = "#define" # Prefix for the const size_t Output
functionPrefix = "" # Prefix for Function Renaming in IDA
offsetPrefix = "" # Prefix for Offset Renaming in IDA

# Globals
Rename = 0
baseAddr = idaapi.get_imagebase()

def SearchOffsetPrev(addr, attempt):
	count = 1
	a = addr
	for i in range(attempt):
		a = PrevNotTail(a)
		# print 'newaddr:', DecToHex(a)
		mnem = GetMnem(a)
		# print mnem
		if mnem == "lea":# or mnem == "add":
			offset = idc.GetOperandValue(a, 1)
			if offset > 6: 
				# print DecToHex(offset), ' count: ', count
				return [count, offset]
		else:
			# print count
			count += 1
	return [count, 0]
		
def SearchOffsetNext(addr, attempt):
	count = 1
	a = addr
	for i in range(attempt):
		a = NextNotTail(a)
		# print 'newaddr:', DecToHex(a)
		mnem = GetMnem(a)
		# print mnem
		if mnem == "lea" or mnem == "add":
			offset = idc.GetOperandValue(a, 1)
			if offset > 6: 
				# print DecToHex(offset), ' count: ', count
				return [count, offset]
		else:
			# print count
			count += 1
	return [count, 0]
		

def FindFuncPattern(Range,Pattern): # Find's Func. by Pattern
	addr = idc.FindBinary(Range, SEARCH_DOWN, Pattern)
	if addr == BADADDR: return 0
	
	try:
		return idaapi.get_func(addr).startEA
	except Exception:
		return 0
		
def FindFuncCall(Range,Pattern): # Find's Func. by Pattern to a Call
	addr = idc.FindBinary(Range, SEARCH_DOWN, Pattern)
	if addr == BADADDR: return 0
	return idc.GetOperandValue(addr, 0)

def FindAddressPattern(Range,Pattern): # Find Offset by Pattern
	addr = idc.FindBinary(Range, SEARCH_DOWN, Pattern)
	if addr == BADADDR: return 0
	
	return addr
    
def FindOffsetPattern(Range,Pattern, Operand): # Find Offset by Pattern
	addr = idc.FindBinary(Range, SEARCH_DOWN, Pattern)
	if addr == BADADDR: return 0
	
	return idc.GetOperandValue(addr, Operand)
# Helpers
#48 ? ? ? ? ? ? 48 ? ? ? ? E8 ? ? ? ? ? ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 81 F7 ? ? ? ? 41 ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ?
def DecToHex(Addr):
	return "0x%0.2X" % Addr



#DECRYPT ID FUNCTION

idoffrange = FindAddressPattern(0,"48 ? ? ? ? ? ? 48 ? ? ? ? E8 ? ? ? ? ? ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 81 F7 ? ? ? ? 41 ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ?")
print "//Start ID Range : " + DecToHex(idoffrange)
print("")

print "#define AActor_ID " + DecToHex(FindOffsetPattern(FindAddressPattern(idoffrange,"41 8B ? ?")+0x1,"41 8B ? ?",1))
print("")

idrange = FindAddressPattern(idoffrange,"81 F3 ?? ??")
print "//Start IDDEC Range : " + DecToHex(idrange)
print("")

xorval1 = (idrange + 2);
usingror = idc.Byte(idrange+7) == 0xCB;
rorval = (idrange + 8);
shiftval = (idrange + 13);
xorval2 = (idrange + 17);

#print "xorval1 = " + DecToHex(idc.GetOperandValue(idrange, 1) & 0xffffffff)
print "#define xorval1 " + DecToHex(idc.GetOperandValue(idrange,1)& 0xffffffff)
if usingror:
    print "#define usingror true"
else:
    print "#define usingror false"

print "#define rorval " + DecToHex(idc.Byte(idrange+8))
print "#define shiftval " + DecToHex(idc.Byte(idrange+13))
print "#define xorval2 " + DecToHex(idc.GetOperandValue(FindAddressPattern(idrange + 2,"35"),1)& 0xffffffff)

print("")
print("")

#UWORLD DECRYPT
uworldrange = FindAddressPattern(0,"0F 57 C9 F3 0F 10 05 ? ? ? ? 0F 2E C1")
print "//Start UWORLD Range : " + DecToHex(uworldrange) + ""
print("")
print "#define XENUINE_DECRYPT_TABLE " + DecToHex(FindFuncCall(uworldrange,"FF 15 ? ? ? ? 48 8B D8"))
print("")
print "#define UWorldBase " + DecToHex(FindOffsetPattern(uworldrange,"48 8B ? ? ? ? ? 48 83 3D ? ? ? ? ?", 1))

#GNAME DECRYPT
gnamerange = FindAddressPattern(0,"48 8D 3D ? ? ? ? 33 C0 B9 ? ? ? ? F3 48 AB 48 8D 3D ? ? ? ? B9 ? ? ? ? F3 48 AB 48 8B 3D")
print("")
print "//Start GNAME Range : " + DecToHex(gnamerange)
print("")
print "#define GNameBase " + DecToHex(FindOffsetPattern(gnamerange,"48 8B 3D ? ? ? ?", 1)-0x30)
print("")

#LOCALPLAYER DECRYPT
print "#define LocalplayerVIP " + DecToHex(FindAddressPattern(0,"A0 0F 00 02 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B4 42") + 0x8)

#CHUNKSIZE DECRYPT
print "#define ChunkSize " + DecToHex(FindOffsetPattern(FindAddressPattern(0,"03 d8 69 c3 ? ? 00 00 2b f0"),"69 C3",2))

#CONTROLLER DECRYPT
playercontrollerrange = FindFuncCall(0,"E8 ? ? ? ? 48 85 C0 74 15 48 8B CB E8 ? ? ? ? 48 85")
print("")
print "//Start PlayerController Range : " + DecToHex(playercontrollerrange)
print("")

print "#define Offset_PlayerController " + DecToHex(FindOffsetPattern(playercontrollerrange,"48 ? ? ? 75 19", 1))

#ACTOR&LEVEL DECRYPT
levelactorrange = FindFuncCall(0,"E8 ? ? ? ? 84 C0 74 16 F6 83 ? ? ? ? ?")
print("")
print "//Start Level&Actor Range : " + DecToHex(levelactorrange)
print("")
#FindOffsetPattern
print "#define World_ULevel " + DecToHex(FindOffsetPattern(levelactorrange,"48 8B 96",1))
print "#define ULevel_Actor " + DecToHex(FindOffsetPattern(FindAddressPattern(FindAddressPattern(levelactorrange,"48 8B 96") + 0x5,"48 8B")+0x2,"48 8B",1)) 

#PROPERTY DECRYPT
propertyrange = FindAddressPattern(0,"83 F9 01 0F 85 ? ? ? ? 4C 8D 86 ? ? ? ? 48 8B D7 48")
print("")
print "//Start Property Range : " + DecToHex(propertyrange)
print("")
print("")
print("")
camera_property = FindAddressPattern(0,"F2 0F ?? ?? ?? ?? ?? ?? F2 0F ?? ?? 8B 81 ?? ?? ?? ?? 89 42 08 F2 0F ?? ?? ?? ?? ?? ?? F2 ?? 0F ?? ?? 8B 81 ?? ?? ?? ?? 41 89 40 08 C3")
print "#define Offset_POV_Location "+ DecToHex(FindOffsetPattern(camera_property,"F2 0F", 1))
print "#define Offset_POV_Rotation "+ DecToHex(FindOffsetPattern(camera_property,"F2 0F ?? ?? ?? ?? ?? ?? F2 ?? ?? ?? ?? 8B", 1))
print "#define Offset_POV_FOV "+ DecToHex(FindOffsetPattern(0,"F3 0F 10 86 ?? ?? ?? ?? 0F 5A C0 F2 0F 11 44 24 20 4C 8B C3 48 8D", 1))
print "#define Offset_BoneArray "+ DecToHex(FindOffsetPattern(FindAddressPattern(0,"0F 84 ?? ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 41")+0x10,"41", 1)-0x8)
print "#define Offset_ComponentToWorld "+ DecToHex(FindOffsetPattern(0,"0F 10 8B ?? ?? ?? ?? 0F 10 83 ?? ?? ?? ?? 0F C2 C1 04 0F 50 C0 0F ?? ?? ?? ?? 85 C0", 1))
print "#define Offset_Health "+ DecToHex(FindOffsetPattern(FindAddressPattern(0,"0F 57 C0 0F 2F 81 ?? ?? ?? ?? 72 0C 0F 2F 81"),"0F 2F", 1))
#print "#define Offset_Mesh "+ DecToHex(FindOffsetPattern(FindAddressPattern(0,"48 8B 99 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 ?? ?? ?? ?? 0F 10")+0x10,"48 8B 99 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 ?? ?? ?? ?? 0F 10", 1))
print "#define Offset_Mesh "+ DecToHex(FindOffsetPattern(0,"48 8B 99 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 ?? ?? ?? ?? 0F 10", 1))
print "#define Offset_UItem "+ DecToHex(FindOffsetPattern(0,"48 8B 93 ?? ?? ?? ?? 0F B6 F8 48 85 D2 74 13 4C 8B CE", 1))
print "#define Offset_DroppedItem "+ DecToHex(FindOffsetPattern(0,"4C 8D A9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 45 8B ? 28 4D 8D 7D 10", 1))
print "#define Offset_AbsoluteLocation "+ DecToHex(FindOffsetPattern(FindAddressPattern(0,"48 85 C0 74 23 0F 10 88 ?? ?? 00 00 0F 28 C1"),"0F 10", 1))
print "#define Offset_RelativeLocation "+ DecToHex(FindOffsetPattern(0,"F2 0F 11 80 ?? ?? ?? ?? 8B 44 24 28 89 83 ?? ?? ?? ?? 0F", 0))
