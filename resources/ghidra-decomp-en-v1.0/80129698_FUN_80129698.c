// Function: FUN_80129698
// Entry: 80129698
// Size: 196 bytes

undefined4 FUN_80129698(char param_1,undefined4 param_2,uint param_3,char param_4)

{
  char cVar1;
  uint uVar2;
  undefined4 uVar3;
  
  uVar3 = FUN_800e8aac();
  uVar2 = countLeadingZeros(10 - (param_3 & 0xff));
  DAT_803dba91 = FUN_800e88b4(param_1,uVar2 >> 5 & 0xff,param_2,uVar3);
  if (((param_4 == '\x02') || (cVar1 = DAT_803dba90, param_4 == '\x01')) &&
     (cVar1 = param_1, DAT_803dba90 == -1)) {
    FUN_8000a518(0x23,1);
    FUN_800206e8(1);
    FUN_80020628(0xff);
    cVar1 = param_1;
  }
  DAT_803dba90 = cVar1;
  return 1;
}

