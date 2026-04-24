// Function: FUN_801c003c
// Entry: 801c003c
// Size: 624 bytes

void FUN_801c003c(int param_1)

{
  char cVar3;
  int iVar1;
  int *piVar2;
  int iVar4;
  int iVar5;
  int local_28 [2];
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  cVar3 = FUN_8002e04c();
  if ((cVar3 != '\0') && (iVar1 = FUN_8001ffb4(0x26b), iVar1 != 0)) {
    FUN_800200e8(0x26b,0);
    piVar2 = (int *)FUN_80036f50(4,local_28);
    iVar1 = 0;
    if (0 < local_28[0]) {
      do {
        iVar4 = *piVar2;
        if ((int)*(short *)(iVar4 + 0x46) == (uint)DAT_80325ce8) {
          iVar1 = iVar1 + 1;
        }
        if ((int)*(short *)(iVar4 + 0x46) == (uint)DAT_80325cea) {
          iVar1 = iVar1 + 1;
        }
        if ((int)*(short *)(iVar4 + 0x46) == (uint)DAT_80325cec) {
          iVar1 = iVar1 + 1;
        }
        if ((int)*(short *)(iVar4 + 0x46) == (uint)DAT_80325cee) {
          iVar1 = iVar1 + 1;
        }
        if ((int)*(short *)(iVar4 + 0x46) == (uint)DAT_80325cf0) {
          iVar1 = iVar1 + 1;
        }
        if ((int)*(short *)(iVar4 + 0x46) == (uint)DAT_80325cf2) {
          iVar1 = iVar1 + 1;
        }
        piVar2 = piVar2 + 1;
        local_28[0] = local_28[0] + -1;
      } while (local_28[0] != 0);
    }
    if (iVar1 < 10) {
      iVar1 = FUN_800221a0(0,5);
      iVar1 = FUN_8002bdf4(0x30,(&DAT_80325ce8)[iVar1]);
      if (iVar1 != 0) {
        *(undefined *)(iVar1 + 0x1a) = 0x14;
        *(undefined2 *)(iVar1 + 0x2c) = 0xffff;
        *(undefined2 *)(iVar1 + 0x1c) = 0xffff;
        uStack28 = FUN_800221a0(0xfffffea2,0x15e);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        *(float *)(iVar1 + 8) =
             *(float *)(param_1 + 0xc) +
             (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e4d90);
        *(float *)(iVar1 + 0xc) = FLOAT_803e4d8c + *(float *)(param_1 + 0x10);
        uStack20 = FUN_800221a0(0xfffffea2,0x15e);
        uStack20 = uStack20 ^ 0x80000000;
        local_18 = 0x43300000;
        *(float *)(iVar1 + 0x10) =
             *(float *)(param_1 + 0x14) +
             (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e4d90);
        *(undefined2 *)(iVar1 + 0x24) = 0xffff;
        *(undefined *)(iVar1 + 4) = *(undefined *)(iVar5 + 4);
        *(undefined *)(iVar1 + 6) = *(undefined *)(iVar5 + 6);
        *(undefined *)(iVar1 + 5) = *(undefined *)(iVar5 + 5);
        *(undefined *)(iVar1 + 7) = *(undefined *)(iVar5 + 7);
        *(undefined2 *)(iVar1 + 0x2e) = 3;
        iVar5 = FUN_8002df90(iVar1,5,(int)*(char *)(param_1 + 0xac),0xffffffff,
                             *(undefined4 *)(param_1 + 0x30));
        if (iVar5 != 0) {
          iVar1 = 3;
          do {
            FUN_80097070((double)FLOAT_803e4d88,iVar5,2,2,100,0);
            iVar1 = iVar1 + -1;
          } while (iVar1 != 0);
        }
      }
    }
  }
  return;
}

