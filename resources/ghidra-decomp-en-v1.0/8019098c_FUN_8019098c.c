// Function: FUN_8019098c
// Entry: 8019098c
// Size: 584 bytes

void FUN_8019098c(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(short *)(iVar2 + 0x20) != -1) {
    iVar1 = FUN_8001ffb4();
    if (iVar1 == 0) {
      *(byte *)(iVar3 + 0xe) = *(byte *)(iVar3 + 0xe) | 0x80;
    }
    else {
      *(byte *)(iVar3 + 0xe) = *(byte *)(iVar3 + 0xe) & 0x7f;
    }
  }
  if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
    FUN_8011f3ec(0x1b);
    iVar1 = FUN_8001ffb4(0x912);
    if (iVar1 == 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
      FUN_800200e8(0x912,1);
      return;
    }
  }
  iVar1 = FUN_8002b9ec();
  if (iVar1 == 0) {
    return;
  }
  if (((*(char *)(iVar3 + 0xd) == '\0') && (*(char *)(iVar3 + 0xc) == '\0')) &&
     ((*(ushort *)(param_1 + 0xb0) & 0x1000) == 0)) {
    if (-1 < DAT_803dceb8) {
      iVar1 = FUN_8002b9ec();
      dVar4 = (double)FUN_80021690(param_1 + 0x18,iVar1 + 0x18);
      if (dVar4 < (double)FLOAT_803e3ee0) {
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
        *(int *)(param_1 + 0xf4) = (int)*(short *)(iVar3 + 8);
        *(undefined *)(iVar3 + 0xd) = 0;
        *(undefined *)(iVar3 + 0xc) = 1;
        DAT_803dcde0 = 2;
        goto LAB_80190b54;
      }
    }
    if (((*(short *)(iVar2 + 0x20) == -1) ||
        ((iVar2 = FUN_8001ffb4(), iVar2 != 0 && ((*(byte *)(param_1 + 0xaf) & 4) != 0)))) &&
       (iVar2 = FUN_80038024(param_1), iVar2 != 0)) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      *(int *)(param_1 + 0xf4) = (int)*(short *)(iVar3 + 8);
      *(undefined *)(iVar3 + 0xd) = 1;
      *(undefined *)(iVar3 + 0xc) = 1;
    }
  }
LAB_80190b54:
  if (*(char *)(iVar3 + 0xc) != '\0') {
    if (*(int *)(param_1 + 0xf4) < 1) {
      *(undefined4 *)(param_1 + 0xf4) = 0;
      *(undefined *)(iVar3 + 0xc) = 0;
    }
    else {
      *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803db410;
    }
  }
  *(float *)(iVar3 + 4) = *(float *)(iVar3 + 4) - FLOAT_803db414;
  if (*(float *)(iVar3 + 4) <= FLOAT_803e3e98) {
    *(float *)(iVar3 + 4) = FLOAT_803e3e98;
    *(undefined2 *)(iVar3 + 10) = 0xffff;
  }
  return;
}

