// Function: FUN_8019d2ac
// Entry: 8019d2ac
// Size: 708 bytes

void FUN_8019d2ac(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int *piVar4;
  
  piVar4 = *(int **)(param_1 + 0xb8);
  piVar4[1] = (int)*(short *)(param_2 + 0x1e);
  iVar3 = FUN_8007fff8(&DAT_80322a48,4,piVar4[1]);
  *piVar4 = iVar3;
  iVar3 = FUN_8007fff8(&DAT_80322a68,3,piVar4[1]);
  piVar4[3] = iVar3;
  if (piVar4[3] == 0) {
    piVar4[3] = -1;
  }
  if (*piVar4 == 0) {
    *piVar4 = 100;
  }
  piVar4[2] = (int)*(short *)(param_2 + 0x1c);
  piVar4[5] = 0;
  if ((int)*(char *)(param_2 + 0x19) == 0) {
    piVar4[0x5c] = (int)FLOAT_803e41cc;
  }
  else {
    piVar4[0x5c] = (int)(FLOAT_803e41c8 *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)*(char *)(param_2 + 0x19) ^ 0x80000000) -
                               DOUBLE_803e41c0));
  }
  *(float *)(param_1 + 8) =
       (*(float *)(*(int *)(param_1 + 0x50) + 4) * (float)piVar4[0x5c]) / FLOAT_803e41cc;
  iVar3 = FUN_8001ffb4(0x57);
  if ((iVar3 != 0) || (9 < *piVar4)) {
    piVar4[5] = 0x3c;
  }
  *(byte *)(piVar4 + 0x5d) = *(byte *)(piVar4 + 0x5d) & 0xbf | 0x40;
  if (piVar4[3] != -1) {
    iVar3 = FUN_8001ffb4();
    if (iVar3 == 0) {
      *(byte *)(piVar4 + 0x5d) = *(byte *)(piVar4 + 0x5d) & 0xbf;
      *(undefined *)(param_1 + 0x36) = 0;
    }
    else {
      piVar4[5] = 0x3c;
    }
  }
  fVar2 = FLOAT_803e416c;
  fVar1 = FLOAT_803e4168;
  iVar3 = 2;
  do {
    *(undefined *)(piVar4 + 10) = 0;
    *(byte *)(piVar4 + 10) = *(byte *)(piVar4 + 10) & 0xe;
    piVar4[7] = (int)fVar1;
    piVar4[9] = (int)fVar2;
    piVar4[8] = (int)fVar2;
    piVar4[6] = 0;
    *(undefined *)((int)piVar4 + 0x29) = 0;
    *(undefined *)(piVar4 + 0x10) = 0;
    *(byte *)(piVar4 + 0x10) = *(byte *)(piVar4 + 0x10) & 0xe;
    piVar4[0xd] = (int)fVar1;
    piVar4[0xf] = (int)fVar2;
    piVar4[0xe] = (int)fVar2;
    piVar4[0xc] = 0;
    *(undefined *)((int)piVar4 + 0x41) = 0;
    *(undefined *)(piVar4 + 0x16) = 0;
    *(byte *)(piVar4 + 0x16) = *(byte *)(piVar4 + 0x16) & 0xe;
    piVar4[0x13] = (int)fVar1;
    piVar4[0x15] = (int)fVar2;
    piVar4[0x14] = (int)fVar2;
    piVar4[0x12] = 0;
    *(undefined *)((int)piVar4 + 0x59) = 0;
    *(undefined *)(piVar4 + 0x1c) = 0;
    *(byte *)(piVar4 + 0x1c) = *(byte *)(piVar4 + 0x1c) & 0xe;
    piVar4[0x19] = (int)fVar1;
    piVar4[0x1b] = (int)fVar2;
    piVar4[0x1a] = (int)fVar2;
    piVar4[0x18] = 0;
    *(undefined *)((int)piVar4 + 0x71) = 0;
    *(undefined *)(piVar4 + 0x22) = 0;
    *(byte *)(piVar4 + 0x22) = *(byte *)(piVar4 + 0x22) & 0xe;
    piVar4[0x1f] = (int)fVar1;
    piVar4[0x21] = (int)fVar2;
    piVar4[0x20] = (int)fVar2;
    piVar4[0x1e] = 0;
    *(undefined *)((int)piVar4 + 0x89) = 0;
    *(undefined *)(piVar4 + 0x28) = 0;
    *(byte *)(piVar4 + 0x28) = *(byte *)(piVar4 + 0x28) & 0xe;
    piVar4[0x25] = (int)fVar1;
    piVar4[0x27] = (int)fVar2;
    piVar4[0x26] = (int)fVar2;
    piVar4[0x24] = 0;
    *(undefined *)((int)piVar4 + 0xa1) = 0;
    *(undefined *)(piVar4 + 0x2e) = 0;
    *(byte *)(piVar4 + 0x2e) = *(byte *)(piVar4 + 0x2e) & 0xe;
    piVar4[0x2b] = (int)fVar1;
    piVar4[0x2d] = (int)fVar2;
    piVar4[0x2c] = (int)fVar2;
    piVar4[0x2a] = 0;
    *(undefined *)((int)piVar4 + 0xb9) = 0;
    piVar4 = piVar4 + 0x2a;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  FUN_80037200(param_1,0x49);
  return;
}

