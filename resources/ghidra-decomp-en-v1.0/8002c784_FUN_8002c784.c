// Function: FUN_8002c784
// Entry: 8002c784
// Size: 872 bytes

void FUN_8002c784(int param_1)

{
  short sVar1;
  int iVar2;
  code *pcVar3;
  
  if ((*(ushort *)(param_1 + 0xb0) & 0x40) != 0) {
    return;
  }
  if ((DAT_803dcb78 & 1) != 0) {
    sVar1 = *(short *)(param_1 + 0x46);
    if (sVar1 != 0x4f3) {
      if (sVar1 < 0x4f3) {
        if (sVar1 != 0x1f) {
          if (0x1e < sVar1) {
            if (sVar1 != 0x69) {
              return;
            }
            FUN_8016eb50();
            return;
          }
          if (sVar1 != 0) {
            return;
          }
        }
        FUN_802b6104(param_1);
        return;
      }
      if (sVar1 != 0x887) {
        if (0x886 < sVar1) {
          return;
        }
        if (sVar1 != 0x882) {
          return;
        }
      }
    }
    (**(code **)(**(int **)(param_1 + 0x68) + 8))(param_1);
    return;
  }
  if (((*(byte *)(param_1 + 0xe5) != 0) && (*(int *)(param_1 + 0xc4) == 0)) &&
     ((*(byte *)(param_1 + 0xe5) & 2) != 0)) {
    FUN_8002aac8();
  }
  if (*(int *)(param_1 + 0xc0) != 0) {
    if ((*(int *)(param_1 + 200) != 0) &&
       (iVar2 = *(int *)(*(int *)(param_1 + 200) + 0x54), iVar2 != 0)) {
      *(undefined4 *)(iVar2 + 0x50) = 0;
      *(undefined *)(*(int *)(*(int *)(param_1 + 200) + 0x54) + 0x71) = 0;
    }
    if (*(int *)(param_1 + 0x54) == 0) {
      return;
    }
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x50) = 0;
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x71) = 0;
    return;
  }
  if ((*(ushort *)(param_1 + 6) & 8) == 0) {
    *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x84) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(param_1 + 0x88) = *(undefined4 *)(param_1 + 0x14);
    *(undefined4 *)(param_1 + 0x8c) = *(undefined4 *)(param_1 + 0x18);
    *(undefined4 *)(param_1 + 0x90) = *(undefined4 *)(param_1 + 0x1c);
    *(undefined4 *)(param_1 + 0x94) = *(undefined4 *)(param_1 + 0x20);
  }
  *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(param_1 + 0x24);
  *(undefined4 *)(param_1 + 0x100) = *(undefined4 *)(param_1 + 0x28);
  *(undefined4 *)(param_1 + 0x104) = *(undefined4 *)(param_1 + 0x2c);
  if (((*(byte *)(param_1 + 0xe5) != 0) && (*(int *)(param_1 + 0xc4) == 0)) &&
     (((*(byte *)(param_1 + 0xe5) & 1) != 0 &&
      (*(short *)(param_1 + 0xe6) =
            (short)(int)((float)((double)CONCAT44(0x43300000,
                                                  (int)*(short *)(param_1 + 0xe6) ^ 0x80000000) -
                                DOUBLE_803de8b0) - FLOAT_803db414), *(short *)(param_1 + 0xe6) < 1))
     )) {
    *(undefined2 *)(param_1 + 0xe6) = 0;
    *(byte *)(param_1 + 0xe5) = *(byte *)(param_1 + 0xe5) & 0xfe;
    *(undefined *)(param_1 + 0xf0) = 0;
    FUN_8002843c(*(undefined4 *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4));
    (**(code **)(*DAT_803dcab4 + 0xc))(param_1,0x7fb,0,0x50,0);
    (**(code **)(*DAT_803dcab4 + 0xc))(param_1,0x7fc,0,0x32,0);
    FUN_8000bb18(param_1,0x47b);
  }
  if ((*(ushort *)(param_1 + 0xb0) & 0x8000) == 0) {
    sVar1 = *(short *)(param_1 + 0x46);
    if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
      FUN_802b6190(param_1);
    }
    else {
      if (*(int **)(param_1 + 0x68) == (int *)0x0) goto LAB_8002ca78;
      pcVar3 = *(code **)(**(int **)(param_1 + 0x68) + 8);
      if (pcVar3 != (code *)0x0) {
        (*pcVar3)(param_1);
      }
    }
    FUN_8000e10c(param_1,param_1 + 0x18,param_1 + 0x1c,param_1 + 0x20);
  }
LAB_8002ca78:
  if (*(int *)(param_1 + 0x54) != 0) {
    if ((*(int *)(param_1 + 200) != 0) &&
       (iVar2 = *(int *)(*(int *)(param_1 + 200) + 0x54), iVar2 != 0)) {
      *(undefined4 *)(iVar2 + 0x50) = 0;
      *(undefined *)(*(int *)(*(int *)(param_1 + 200) + 0x54) + 0x71) = 0;
    }
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x50) = 0;
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x71) = 0;
  }
  if (*(int *)(param_1 + 0x58) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x58) + 0x10f) = 0;
  }
  return;
}

