// Function: FUN_80227dc4
// Entry: 80227dc4
// Size: 1032 bytes

void FUN_80227dc4(short *param_1)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  ushort uVar4;
  int *piVar5;
  float local_18 [2];
  longlong local_10;
  
  local_18[0] = FLOAT_803e7a8c;
  piVar5 = *(int **)(param_1 + 0x5c);
  if (*piVar5 == 0) {
    iVar2 = FUN_80036f50(9,param_1,local_18);
    *piVar5 = iVar2;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  else {
    local_10 = (longlong)(int)(FLOAT_803e7a90 * FLOAT_803dc074);
    *param_1 = *param_1 + (short)(int)(FLOAT_803e7a90 * FLOAT_803dc074);
    if (*(short *)((int)piVar5 + 10) != 5) {
      if (*(char *)((int)param_1 + 0xad) == '\x01') {
        uVar3 = FUN_80020078(0x812);
        if (uVar3 == 0) {
          uVar3 = FUN_80020078(0x808);
          if (uVar3 != 0) {
            *(undefined2 *)((int)piVar5 + 10) = 3;
          }
        }
        else {
          *(undefined2 *)((int)piVar5 + 10) = 5;
        }
      }
      else {
        uVar3 = FUN_80020078(0x813);
        if (uVar3 == 0) {
          uVar3 = FUN_80020078(0x809);
          if (uVar3 != 0) {
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
      iVar2 = (uint)*(byte *)(param_1 + 0x1b) + (uint)DAT_803dc070 * -8;
      if (iVar2 < 0) {
        iVar2 = 0;
      }
      *(char *)(param_1 + 0x1b) = (char)iVar2;
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
          uVar3 = (uint)*(byte *)(param_1 + 0x1b) + (uint)DAT_803dc070 * 8;
          if (0xff < uVar3) {
            uVar3 = 0xff;
          }
          *(char *)(param_1 + 0x1b) = (char)uVar3;
          if (*(char *)(param_1 + 0x1b) != -1) {
            return;
          }
          *(undefined2 *)((int)piVar5 + 10) = 1;
          return;
        }
      }
      uVar3 = (uint)*(byte *)(param_1 + 0x1b) + (uint)DAT_803dc070 * 8;
      if (0xff < uVar3) {
        uVar3 = 0xff;
      }
      *(char *)(param_1 + 0x1b) = (char)uVar3;
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

