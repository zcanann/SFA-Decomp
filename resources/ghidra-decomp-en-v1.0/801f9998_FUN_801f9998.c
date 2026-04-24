// Function: FUN_801f9998
// Entry: 801f9998
// Size: 672 bytes

/* WARNING: Removing unreachable block (ram,0x801f9a8c) */

void FUN_801f9998(int param_1)

{
  int iVar1;
  int iVar2;
  byte bVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8002b9ec();
  if ((*(int *)(param_1 + 0xf4) == 0) && (iVar2 = FUN_8001ffb4(0xef6), iVar2 == 0)) {
    iVar2 = FUN_8001ffb4(0xd72);
    if (iVar2 != 0) {
      FUN_80008b74(param_1,param_1,0x10c,0);
      FUN_80008b74(param_1,param_1,0x10d,0);
      FUN_80008b74(param_1,param_1,0x10e,0);
      FUN_80088e54((double)FLOAT_803e6060,1);
      FUN_800200e8(0xd72,0);
    }
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  FUN_8005afac((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x14));
  bVar3 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  if (bVar3 == 2) {
    if ((DAT_803dc148 != 0) &&
       (DAT_803dc148 = DAT_803dc148 - (short)(int)FLOAT_803db414, DAT_803dc148 < 1)) {
      DAT_803dc148 = 0;
    }
    FUN_801f9804(param_1);
  }
  else if (bVar3 < 2) {
    if (bVar3 != 0) {
      if ((DAT_803dc148 != 0) &&
         (DAT_803dc148 = DAT_803dc148 - (short)(int)FLOAT_803db414, DAT_803dc148 < 1)) {
        DAT_803dc148 = 0;
      }
      FUN_8002b9ec();
      iVar1 = FUN_8001ffb4(0x4ec);
      if (((iVar1 == 0) && (iVar1 = FUN_8001ffb4(0x9b1), iVar1 != 0)) &&
         (iVar1 = FUN_8001ffb4(0x9b2), iVar1 != 0)) {
        FUN_800200e8(0x4ec,1);
      }
      iVar1 = FUN_8001ffb4(0xd6d);
      if (((iVar1 != 0) && (iVar1 = FUN_8001ffb4(0xd6e), iVar1 != 0)) &&
         ((iVar1 = FUN_8001ffb4(0xd6f), iVar1 != 0 && (iVar1 = FUN_8001ffb4(0xd70), iVar1 != 0)))) {
        FUN_800200e8(0xcfb,1);
      }
    }
  }
  else if (bVar3 < 4) {
    if ((DAT_803dc148 != 0) &&
       (DAT_803dc148 = DAT_803dc148 - (short)(int)FLOAT_803db414, DAT_803dc148 < 1)) {
      DAT_803dc148 = 0;
    }
    FUN_8002b9ec();
  }
  FUN_801d7ed4(iVar4 + 0x14,1,0xffffffff,0xffffffff,0xdcf,0xe1);
  FUN_801d7ed4(iVar4 + 0x14,2,0xffffffff,0xffffffff,0xdcf,0x96);
  return;
}

