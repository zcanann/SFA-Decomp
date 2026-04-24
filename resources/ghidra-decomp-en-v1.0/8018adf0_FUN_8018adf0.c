// Function: FUN_8018adf0
// Entry: 8018adf0
// Size: 472 bytes

/* WARNING: Removing unreachable block (ram,0x8018ae40) */

void FUN_8018adf0(short *param_1)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  byte *pbVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x26);
  pbVar4 = *(byte **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(iVar5 + 0x1a) << 8;
  bVar1 = *pbVar4;
  if (bVar1 == 2) {
    if ((*(byte *)((int)param_1 + 0xaf) & 4) != 0) {
      FUN_8011f3ec(0x19);
    }
    iVar2 = FUN_80038024(param_1);
    if (iVar2 == 0) {
      FUN_80041018(param_1);
    }
    else {
      *pbVar4 = 3;
      if (*(char *)(iVar5 + 0x1b) == '\0') {
        (**(code **)(*DAT_803dca54 + 0x48))(3,param_1,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
      }
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      FUN_800200e8(0xefb,1);
      FUN_800887f8(0);
      FUN_80008cbc(param_1,param_1,0x2c,0);
      FUN_80008cbc(param_1,param_1,0x2d,0);
      *pbVar4 = 1;
      if (*(char *)(iVar5 + 0x1b) == '\0') {
        (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      }
    }
    else {
      FUN_8000a518(0x2f,1);
      *pbVar4 = 2;
    }
  }
  else if (bVar1 < 4) {
    FUN_800200e8(0x91e,1);
    uVar3 = FUN_8001ffb4(0x1b8);
    FUN_800552e8(uVar3,0);
  }
  return;
}

