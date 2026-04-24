// Function: FUN_80159654
// Entry: 80159654
// Size: 488 bytes

void FUN_80159654(int param_1,int param_2)

{
  short sVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  *(undefined4 *)(param_2 + 0x2e4) = 0xb;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x400b0;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x40001040;
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x6a3) {
    *(float *)(param_2 + 0x2ac) = FLOAT_803e2be4;
    *(float *)(param_2 + 0x2a8) = FLOAT_803e2bb8;
    *(undefined2 *)(param_2 + 0x2b0) = 0x1e;
    *(undefined *)(param_2 + 0x33b) = 0;
    *(undefined *)(param_2 + 800) = 9;
    fVar2 = FLOAT_803e2be8;
    *(float *)(param_2 + 0x314) = FLOAT_803e2be8;
    *(undefined *)(param_2 + 0x321) = 0xc;
    *(float *)(param_2 + 0x318) = FLOAT_803e2bec;
    *(undefined *)(param_2 + 0x322) = 9;
    *(float *)(param_2 + 0x31c) = fVar2;
    *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x400;
  }
  else if (sVar1 < 0x6a3) {
    if (0x6a1 < sVar1) {
      *(float *)(param_2 + 0x2ac) = FLOAT_803e2bf0;
      *(float *)(param_2 + 0x2a8) = FLOAT_803e2bb8;
      *(undefined2 *)(param_2 + 0x2b0) = 0x32;
      *(undefined *)(param_2 + 0x33b) = 1;
      *(undefined *)(param_2 + 800) = 0xe;
      fVar2 = FLOAT_803e2be8;
      *(float *)(param_2 + 0x314) = FLOAT_803e2be8;
      *(undefined *)(param_2 + 0x321) = 0xd;
      *(float *)(param_2 + 0x318) = FLOAT_803e2bec;
      *(undefined *)(param_2 + 0x322) = 0xe;
      *(float *)(param_2 + 0x31c) = fVar2;
      *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0xc00;
    }
  }
  else if (sVar1 < 0x6a5) {
    *(float *)(param_2 + 0x2ac) = FLOAT_803e2bf4;
    *(float *)(param_2 + 0x2a8) = FLOAT_803e2bf8;
    *(undefined2 *)(param_2 + 0x2b0) = 0xf;
    *(undefined *)(param_2 + 0x33b) = 2;
    *(undefined *)(param_2 + 800) = 0xd;
    fVar2 = FLOAT_803e2be8;
    *(float *)(param_2 + 0x314) = FLOAT_803e2be8;
    *(undefined *)(param_2 + 0x321) = 0x10;
    *(float *)(param_2 + 0x318) = FLOAT_803e2bec;
    *(undefined *)(param_2 + 0x322) = 0xd;
    *(float *)(param_2 + 0x31c) = fVar2;
    *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0xc00;
  }
  *(float *)(param_2 + 0x308) = FLOAT_803e2bd4;
  *(float *)(param_2 + 0x300) = FLOAT_803e2bfc;
  *(float *)(param_2 + 0x304) = FLOAT_803e2c00;
  *(float *)(param_2 + 0x2fc) = *(float *)(param_2 + 0x2fc) * FLOAT_803e2c04;
  if (*(char *)(iVar3 + 0x2e) != -1) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 1;
  }
  *(float *)(param_1 + 8) =
       FLOAT_803e2c08 +
       (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar3 + 0x28) ^ 0x80000000) -
              DOUBLE_803e2b98) / FLOAT_803e2c0c;
  return;
}

