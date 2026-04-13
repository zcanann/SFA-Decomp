// Function: FUN_801f9fd0
// Entry: 801f9fd0
// Size: 672 bytes

/* WARNING: Removing unreachable block (ram,0x801fa0c4) */

void FUN_801f9fd0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  byte bVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  undefined8 uVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  FUN_8002bac4();
  if ((*(int *)(param_9 + 0xf4) == 0) && (uVar1 = FUN_80020078(0xef6), uVar1 == 0)) {
    uVar1 = FUN_80020078(0xd72);
    if (uVar1 != 0) {
      uVar4 = FUN_80008b74(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x10c,0,in_r7,in_r8,in_r9,in_r10);
      uVar4 = FUN_80008b74(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x10d,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80008b74(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x10e,0,in_r7,in_r8,in_r9,in_r10);
      FUN_800890e0((double)FLOAT_803e6cf8,1);
      FUN_800201ac(0xd72,0);
    }
    *(undefined4 *)(param_9 + 0xf4) = 1;
  }
  FUN_8005b128();
  bVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
  if (bVar2 == 2) {
    if ((DAT_803dcdb0 != 0) &&
       (DAT_803dcdb0 = DAT_803dcdb0 - (short)(int)FLOAT_803dc074, DAT_803dcdb0 < 1)) {
      DAT_803dcdb0 = 0;
    }
    FUN_801f9e3c(param_9);
  }
  else if (bVar2 < 2) {
    if (bVar2 != 0) {
      if ((DAT_803dcdb0 != 0) &&
         (DAT_803dcdb0 = DAT_803dcdb0 - (short)(int)FLOAT_803dc074, DAT_803dcdb0 < 1)) {
        DAT_803dcdb0 = 0;
      }
      FUN_8002bac4();
      uVar1 = FUN_80020078(0x4ec);
      if (((uVar1 == 0) && (uVar1 = FUN_80020078(0x9b1), uVar1 != 0)) &&
         (uVar1 = FUN_80020078(0x9b2), uVar1 != 0)) {
        FUN_800201ac(0x4ec,1);
      }
      uVar1 = FUN_80020078(0xd6d);
      if (((uVar1 != 0) && (uVar1 = FUN_80020078(0xd6e), uVar1 != 0)) &&
         ((uVar1 = FUN_80020078(0xd6f), uVar1 != 0 && (uVar1 = FUN_80020078(0xd70), uVar1 != 0)))) {
        FUN_800201ac(0xcfb,1);
      }
    }
  }
  else if (bVar2 < 4) {
    if ((DAT_803dcdb0 != 0) &&
       (DAT_803dcdb0 = DAT_803dcdb0 - (short)(int)FLOAT_803dc074, DAT_803dcdb0 < 1)) {
      DAT_803dcdb0 = 0;
    }
    FUN_8002bac4();
  }
  FUN_801d84c4(iVar3 + 0x14,1,-1,-1,0xdcf,(int *)0xe1);
  FUN_801d84c4(iVar3 + 0x14,2,-1,-1,0xdcf,(int *)0x96);
  return;
}

