// Function: FUN_8022771c
// Entry: 8022771c
// Size: 1032 bytes

void FUN_8022771c(short *param_1)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  ushort uVar4;
  int *piVar5;
  float local_18 [2];
  longlong local_10;
  
  local_18[0] = FLOAT_803e6df4;
  piVar5 = *(int **)(param_1 + 0x5c);
  if (*piVar5 == 0) {
    iVar3 = FUN_80036e58(9,param_1,local_18);
    *piVar5 = iVar3;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  else {
    local_10 = (longlong)(int)(FLOAT_803e6df8 * FLOAT_803db414);
    *param_1 = *param_1 + (short)(int)(FLOAT_803e6df8 * FLOAT_803db414);
    if (*(short *)((int)piVar5 + 10) != 5) {
      if (*(char *)((int)param_1 + 0xad) == '\x01') {
        iVar3 = FUN_8001ffb4(0x812);
        if (iVar3 == 0) {
          iVar3 = FUN_8001ffb4(0x808);
          if (iVar3 != 0) {
            *(undefined2 *)((int)piVar5 + 10) = 3;
          }
        }
        else {
          *(undefined2 *)((int)piVar5 + 10) = 5;
        }
      }
      else {
        iVar3 = FUN_8001ffb4(0x813);
        if (iVar3 == 0) {
          iVar3 = FUN_8001ffb4(0x809);
          if (iVar3 != 0) {
            *(undefined2 *)((int)piVar5 + 10) = 3;
          }
        }
        else {
          *(undefined2 *)((int)piVar5 + 10) = 5;
        }
      }
    }
    sVar1 = *(short *)((int)piVar5 + 10);
    if (sVar1 == 3) {
      iVar3 = (uint)*(byte *)(param_1 + 0x1b) + (uint)DAT_803db410 * -8;
      if (iVar3 < 0) {
        iVar3 = 0;
      }
      *(char *)(param_1 + 0x1b) = (char)iVar3;
      if (*(char *)(param_1 + 0x1b) == '\0') {
        if (*(char *)((int)param_1 + 0xad) == '\x01') {
          (**(code **)(**(int **)(*piVar5 + 0x68) + 0x30))
                    ((int)*(short *)(piVar5 + 2),piVar5 + 1,(int)piVar5 + 6);
          (**(code **)(**(int **)(*piVar5 + 0x68) + 0x20))
                    (param_1,(int)*(short *)(piVar5 + 1),(int)*(short *)((int)piVar5 + 6),
                     param_1 + 6,param_1 + 10);
          *(undefined2 *)((int)piVar5 + 10) = 4;
        }
        else {
          (**(code **)(**(int **)(*piVar5 + 0x68) + 0x4c))
                    ((int)*(short *)(piVar5 + 2),piVar5 + 1,(int)piVar5 + 6);
          (**(code **)(**(int **)(*piVar5 + 0x68) + 0x3c))
                    (param_1,(int)*(short *)(piVar5 + 1),(int)*(short *)((int)piVar5 + 6),
                     param_1 + 6,param_1 + 10);
          *(undefined2 *)((int)piVar5 + 10) = 4;
        }
      }
    }
    else {
      if (sVar1 < 3) {
        if (sVar1 != 1) {
          if (0 < sVar1) {
            *(undefined *)(param_1 + 0x1b) = 0;
            return;
          }
          if (-1 < sVar1) {
            if (*(char *)((int)param_1 + 0xad) == '\x01') {
              (**(code **)(**(int **)(*piVar5 + 0x68) + 0x30))
                        ((int)*(short *)(piVar5 + 2),piVar5 + 1,(int)piVar5 + 6);
              (**(code **)(**(int **)(*piVar5 + 0x68) + 0x20))
                        (param_1,(int)*(short *)(piVar5 + 1),(int)*(short *)((int)piVar5 + 6),
                         param_1 + 6,param_1 + 10);
            }
            else {
              (**(code **)(**(int **)(*piVar5 + 0x68) + 0x4c))
                        ((int)*(short *)(piVar5 + 2),piVar5 + 1,(int)piVar5 + 6);
              (**(code **)(**(int **)(*piVar5 + 0x68) + 0x3c))
                        (param_1,(int)*(short *)(piVar5 + 1),(int)*(short *)((int)piVar5 + 6),
                         param_1 + 6,param_1 + 10);
            }
            *(undefined *)(param_1 + 0x1b) = 0xff;
            *(undefined2 *)((int)piVar5 + 10) = 1;
            return;
          }
        }
      }
      else {
        if (sVar1 == 5) {
          *(undefined *)(param_1 + 0x1b) = 0;
          return;
        }
        if (sVar1 < 5) {
          uVar2 = (uint)*(byte *)(param_1 + 0x1b) + (uint)DAT_803db410 * 8;
          if (0xff < uVar2) {
            uVar2 = 0xff;
          }
          *(char *)(param_1 + 0x1b) = (char)uVar2;
          if (*(char *)(param_1 + 0x1b) != -1) {
            return;
          }
          *(undefined2 *)((int)piVar5 + 10) = 1;
          return;
        }
      }
      uVar2 = (uint)*(byte *)(param_1 + 0x1b) + (uint)DAT_803db410 * 8;
      if (0xff < uVar2) {
        uVar2 = 0xff;
      }
      *(char *)(param_1 + 0x1b) = (char)uVar2;
      if (*(char *)((int)param_1 + 0xad) == '\x01') {
        uVar4 = (**(code **)(**(int **)(*piVar5 + 0x68) + 0x2c))
                          ((int)*(short *)(piVar5 + 1),(int)*(short *)((int)piVar5 + 6));
        if (*(ushort *)(piVar5 + 2) != (uVar4 & 0xff)) {
          *(undefined2 *)((int)piVar5 + 10) = 2;
        }
      }
      else {
        uVar4 = (**(code **)(**(int **)(*piVar5 + 0x68) + 0x48))
                          ((int)*(short *)(piVar5 + 1),(int)*(short *)((int)piVar5 + 6));
        if (*(ushort *)(piVar5 + 2) != (uVar4 & 0xff)) {
          *(undefined2 *)((int)piVar5 + 10) = 2;
        }
      }
    }
  }
  return;
}

