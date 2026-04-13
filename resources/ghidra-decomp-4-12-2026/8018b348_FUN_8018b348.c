// Function: FUN_8018b348
// Entry: 8018b348
// Size: 472 bytes

/* WARNING: Removing unreachable block (ram,0x8018b398) */

void FUN_8018b348(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  int iVar5;
  undefined8 uVar6;
  
  iVar5 = *(int *)(param_9 + 0x26);
  pbVar4 = *(byte **)(param_9 + 0x5c);
  *param_9 = (ushort)*(byte *)(iVar5 + 0x1a) << 8;
  bVar1 = *pbVar4;
  if (bVar1 == 2) {
    if ((*(byte *)((int)param_9 + 0xaf) & 4) != 0) {
      FUN_8011f6d0(0x19);
    }
    iVar2 = FUN_8003811c((int)param_9);
    if (iVar2 == 0) {
      FUN_80041110();
    }
    else {
      *pbVar4 = 3;
      if (*(char *)(iVar5 + 0x1b) == '\0') {
        (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_9,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
      }
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      uVar6 = FUN_800201ac(0xefb,1);
      uVar6 = FUN_80088a84(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
      uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x2c,0,param_13,param_14,param_15,param_16);
      FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x2d,0,param_13,param_14,param_15,param_16);
      *pbVar4 = 1;
      if (*(char *)(iVar5 + 0x1b) == '\0') {
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_9,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
      }
    }
    else {
      FUN_8000a538((int *)0x2f,1);
      *pbVar4 = 2;
    }
  }
  else if (bVar1 < 4) {
    uVar6 = FUN_800201ac(0x91e,1);
    uVar3 = FUN_80020078(0x1b8);
    FUN_80055464(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,'\0',param_11,
                 param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

