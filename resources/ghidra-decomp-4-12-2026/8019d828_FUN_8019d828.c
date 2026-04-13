// Function: FUN_8019d828
// Entry: 8019d828
// Size: 708 bytes

void FUN_8019d828(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  
  piVar5 = *(int **)(param_1 + 0xb8);
  piVar5[1] = (int)*(short *)(param_2 + 0x1e);
  iVar3 = FUN_80080284((int *)&DAT_80323698,4,piVar5[1]);
  *piVar5 = iVar3;
  iVar3 = FUN_80080284((int *)&DAT_803236b8,3,piVar5[1]);
  piVar5[3] = iVar3;
  if (piVar5[3] == 0) {
    piVar5[3] = -1;
  }
  if (*piVar5 == 0) {
    *piVar5 = 100;
  }
  piVar5[2] = (int)*(short *)(param_2 + 0x1c);
  piVar5[5] = 0;
  if ((int)*(char *)(param_2 + 0x19) == 0) {
    piVar5[0x5c] = (int)FLOAT_803e4e64;
  }
  else {
    piVar5[0x5c] = (int)(FLOAT_803e4e60 *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)*(char *)(param_2 + 0x19) ^ 0x80000000) -
                               DOUBLE_803e4e58));
  }
  *(float *)(param_1 + 8) =
       (*(float *)(*(int *)(param_1 + 0x50) + 4) * (float)piVar5[0x5c]) / FLOAT_803e4e64;
  uVar4 = FUN_80020078(0x57);
  if ((uVar4 != 0) || (9 < *piVar5)) {
    piVar5[5] = 0x3c;
  }
  *(byte *)(piVar5 + 0x5d) = *(byte *)(piVar5 + 0x5d) & 0xbf | 0x40;
  if (piVar5[3] != 0xffffffff) {
    uVar4 = FUN_80020078(piVar5[3]);
    if (uVar4 == 0) {
      *(byte *)(piVar5 + 0x5d) = *(byte *)(piVar5 + 0x5d) & 0xbf;
      *(undefined *)(param_1 + 0x36) = 0;
    }
    else {
      piVar5[5] = 0x3c;
    }
  }
  fVar2 = FLOAT_803e4e04;
  fVar1 = FLOAT_803e4e00;
  iVar3 = 2;
  do {
    *(undefined *)(piVar5 + 10) = 0;
    *(byte *)(piVar5 + 10) = *(byte *)(piVar5 + 10) & 0xe;
    piVar5[7] = (int)fVar1;
    piVar5[9] = (int)fVar2;
    piVar5[8] = (int)fVar2;
    piVar5[6] = 0;
    *(undefined *)((int)piVar5 + 0x29) = 0;
    *(undefined *)(piVar5 + 0x10) = 0;
    *(byte *)(piVar5 + 0x10) = *(byte *)(piVar5 + 0x10) & 0xe;
    piVar5[0xd] = (int)fVar1;
    piVar5[0xf] = (int)fVar2;
    piVar5[0xe] = (int)fVar2;
    piVar5[0xc] = 0;
    *(undefined *)((int)piVar5 + 0x41) = 0;
    *(undefined *)(piVar5 + 0x16) = 0;
    *(byte *)(piVar5 + 0x16) = *(byte *)(piVar5 + 0x16) & 0xe;
    piVar5[0x13] = (int)fVar1;
    piVar5[0x15] = (int)fVar2;
    piVar5[0x14] = (int)fVar2;
    piVar5[0x12] = 0;
    *(undefined *)((int)piVar5 + 0x59) = 0;
    *(undefined *)(piVar5 + 0x1c) = 0;
    *(byte *)(piVar5 + 0x1c) = *(byte *)(piVar5 + 0x1c) & 0xe;
    piVar5[0x19] = (int)fVar1;
    piVar5[0x1b] = (int)fVar2;
    piVar5[0x1a] = (int)fVar2;
    piVar5[0x18] = 0;
    *(undefined *)((int)piVar5 + 0x71) = 0;
    *(undefined *)(piVar5 + 0x22) = 0;
    *(byte *)(piVar5 + 0x22) = *(byte *)(piVar5 + 0x22) & 0xe;
    piVar5[0x1f] = (int)fVar1;
    piVar5[0x21] = (int)fVar2;
    piVar5[0x20] = (int)fVar2;
    piVar5[0x1e] = 0;
    *(undefined *)((int)piVar5 + 0x89) = 0;
    *(undefined *)(piVar5 + 0x28) = 0;
    *(byte *)(piVar5 + 0x28) = *(byte *)(piVar5 + 0x28) & 0xe;
    piVar5[0x25] = (int)fVar1;
    piVar5[0x27] = (int)fVar2;
    piVar5[0x26] = (int)fVar2;
    piVar5[0x24] = 0;
    *(undefined *)((int)piVar5 + 0xa1) = 0;
    *(undefined *)(piVar5 + 0x2e) = 0;
    *(byte *)(piVar5 + 0x2e) = *(byte *)(piVar5 + 0x2e) & 0xe;
    piVar5[0x2b] = (int)fVar1;
    piVar5[0x2d] = (int)fVar2;
    piVar5[0x2c] = (int)fVar2;
    piVar5[0x2a] = 0;
    *(undefined *)((int)piVar5 + 0xb9) = 0;
    piVar5 = piVar5 + 0x2a;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  FUN_800372f8(param_1,0x49);
  return;
}

