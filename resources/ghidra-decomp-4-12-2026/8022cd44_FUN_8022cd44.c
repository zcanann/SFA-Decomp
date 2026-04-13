// Function: FUN_8022cd44
// Entry: 8022cd44
// Size: 292 bytes

void FUN_8022cd44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  char cVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined8 uVar5;
  
  cVar1 = *(char *)(param_9 + 0xac);
  if (cVar1 == '<') {
    FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,99,'\0',param_11,
                 param_12,param_13,param_14,param_15,param_16);
  }
  else if (cVar1 < '<') {
    if (cVar1 == ':') {
      uVar2 = FUN_80020078(0xc85);
      if (uVar2 == 0) {
        FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x6c,'\0',
                     param_11,param_12,param_13,param_14,param_15,param_16);
      }
      else {
        FUN_800201ac(0x405,0);
        (**(code **)(*DAT_803dd72c + 0x44))(0xb,5);
        (**(code **)(*DAT_803dd72c + 0x50))(0xb,10,1);
        uVar3 = 1;
        iVar4 = *DAT_803dd72c;
        uVar5 = (**(code **)(iVar4 + 0x50))(0xb,0xb);
        FUN_80055464(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x22,'\0',uVar3,
                     iVar4,param_13,param_14,param_15,param_16);
      }
    }
    else if ('9' < cVar1) {
      FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x77,'\0',
                   param_11,param_12,param_13,param_14,param_15,param_16);
    }
  }
  else if (cVar1 == '>') {
    FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x79,'\0',param_11,
                 param_12,param_13,param_14,param_15,param_16);
  }
  else if (cVar1 < '>') {
    FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x78,'\0',param_11,
                 param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

