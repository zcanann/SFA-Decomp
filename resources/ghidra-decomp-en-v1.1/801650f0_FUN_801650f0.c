// Function: FUN_801650f0
// Entry: 801650f0
// Size: 672 bytes

void FUN_801650f0(uint param_1)

{
  short sVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar4 + 0x27a) & 1) != 0) {
    sVar1 = *(short *)(param_1 + 0x46);
    if (sVar1 == 0x4ba) {
LAB_80165148:
      iVar3 = 0x14;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x34d,0,2,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    else {
      if (sVar1 < 0x4ba) {
        if (sVar1 == 0x39d) goto LAB_80165148;
      }
      else if (sVar1 == 0x4c1) goto LAB_80165148;
      iVar3 = 0x14;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x32e,0,2,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    FUN_8000bb38(param_1,0x27d);
    *(byte *)(iVar4 + 0x27a) = *(byte *)(iVar4 + 0x27a) & 0xfe;
  }
  if ((*(byte *)(iVar4 + 0x27a) & 2) == 0) goto LAB_80165284;
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x4ba) {
LAB_80165218:
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x34c,0,2,0xffffffff,0);
  }
  else {
    if (sVar1 < 0x4ba) {
      if (sVar1 == 0x39d) goto LAB_80165218;
    }
    else if (sVar1 == 0x4c1) goto LAB_80165218;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x32d,0,2,0xffffffff,0);
  }
  *(byte *)(iVar4 + 0x27a) = *(byte *)(iVar4 + 0x27a) & 0xfd;
LAB_80165284:
  if ((*(byte *)(iVar4 + 0x27a) & 4) != 0) {
    *(undefined *)(param_1 + 0x36) = 0;
    *(undefined *)(iVar4 + 0x278) = 5;
    *(float *)(iVar4 + 0x270) = FLOAT_803e3c60;
    FUN_80035ff8(param_1);
    *(byte *)(iVar4 + 0x27a) = *(byte *)(iVar4 + 0x27a) & 0xfb;
  }
  if (((*(byte *)(iVar4 + 0x27a) & 0x10) != 0) && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    FUN_80035eec(param_1,0x1f,1,0);
    bVar2 = *(char *)(iVar4 + 0x27b) + 1;
    *(byte *)(iVar4 + 0x27b) = bVar2;
    if ((uint)bVar2 % 6 == 0) {
      FUN_80098da4(param_1,1,3,0,(undefined4 *)0x0);
    }
    else {
      FUN_80098da4(param_1,1,0,0,(undefined4 *)0x0);
    }
    FUN_8000da78(param_1,0x451);
  }
  return;
}

