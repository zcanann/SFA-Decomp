// Function: FUN_801766e8
// Entry: 801766e8
// Size: 716 bytes

void FUN_801766e8(int param_1)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  *(ushort *)(iVar4 + 0x100) = *(ushort *)(iVar4 + 0x100) & 0xfffd;
  *(byte *)(iVar4 + 0x114) = *(byte *)(iVar4 + 0x114) & 0x7f;
  if (FLOAT_803e3528 != *(float *)(param_1 + 0x28)) {
    *(ushort *)(iVar4 + 0x100) = *(ushort *)(iVar4 + 0x100) | 2;
  }
  if ((*(byte *)(iVar4 + 0x114) >> 6 & 1) == 0) {
    FUN_8002b9ec();
    iVar2 = FUN_80295cd4();
    if (iVar2 != 0) goto LAB_80176780;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
LAB_80176780:
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  if (((*(byte *)(param_1 + 0xaf) & 4) != 0) && (iVar2 = FUN_8001ffb4(0x913), iVar2 == 0)) {
    (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    FUN_800200e8(0x913,1);
    return;
  }
  iVar2 = FUN_8002b9ec();
  if (((iVar2 != 0) && (iVar2 = FUN_80295a04(iVar2,10), iVar2 != 0)) ||
     ((*(ushort *)(iVar4 + 0x100) & 4) != 0)) {
    *(undefined *)(iVar4 + 0x145) = 0x78;
  }
  if (*(char *)(iVar4 + 0x145) == '\0') {
    if (*(char *)(iVar4 + 0x146) != '\0') {
      FUN_800e8054(param_1);
    }
  }
  else {
    *(char *)(iVar4 + 0x145) = *(char *)(iVar4 + 0x145) + -1;
  }
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x411) {
    iVar3 = FUN_80174668(param_1,iVar4);
  }
  else {
    if (0x410 < sVar1) {
      if (sVar1 == 0x54a) {
        iVar2 = FUN_8001ffb4((int)*(short *)(iVar4 + 0xac));
        if (iVar2 != 0) {
          *(float *)(param_1 + 0xc) = (float)((double)*(float *)(iVar3 + 8) - DOUBLE_803e3530);
          *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0xc);
          *(float *)(param_1 + 0x14) = (float)(DOUBLE_803e3538 + (double)*(float *)(iVar3 + 0x10));
        }
        FUN_80174438(param_1,iVar4);
      }
      goto LAB_80176958;
    }
    if (sVar1 != 0x21e) {
      if ((sVar1 < 0x21e) && (sVar1 == 0x108)) {
        if ((FLOAT_803e3528 == *(float *)(iVar4 + 0xf8)) &&
           (FLOAT_803e3528 < *(float *)(iVar4 + 0xf4))) {
          FUN_8000bb18(param_1,0x68);
          FUN_800200e8(0x272,1);
        }
        iVar3 = FUN_8001ffb4(0x272);
        if (iVar3 != 0) {
          FUN_8002ce88(param_1);
          FUN_80035f00(param_1);
          *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
        }
      }
      goto LAB_80176958;
    }
    iVar3 = FUN_80174668(param_1,iVar4);
  }
  if (iVar3 != 0) {
    return;
  }
LAB_80176958:
  sVar1 = *(short *)(param_1 + 0x46);
  if (((sVar1 != 0x54a) && (sVar1 != 0x5ae)) &&
     ((sVar1 != 0x108 &&
      ((*(char *)(iVar4 + 0x146) != '\0' && ((*(ushort *)(iVar4 + 0x100) & 8) == 0)))))) {
    FUN_800e8370(param_1);
  }
  return;
}

