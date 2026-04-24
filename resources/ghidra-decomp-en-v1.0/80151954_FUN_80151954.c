// Function: FUN_80151954
// Entry: 80151954
// Size: 788 bytes

void FUN_80151954(int param_1,int param_2)

{
  short sVar1;
  float fVar2;
  undefined4 uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  *(undefined4 *)(param_2 + 0x2e4) = 0xb;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x402b0;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x3040;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x40300000;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0xc00;
  *(float *)(param_2 + 0x308) = FLOAT_803e2754;
  *(float *)(param_2 + 0x300) = FLOAT_803e27b0;
  *(float *)(param_2 + 0x304) = FLOAT_803e27b4;
  *(undefined *)(param_2 + 800) = 0x23;
  fVar2 = FLOAT_803e2748;
  *(float *)(param_2 + 0x314) = FLOAT_803e2748;
  *(undefined *)(param_2 + 0x321) = 0x22;
  *(float *)(param_2 + 0x318) = FLOAT_803e27b8;
  *(undefined *)(param_2 + 0x322) = 6;
  *(float *)(param_2 + 0x31c) = fVar2;
  *(float *)(param_2 + 0x2fc) = *(float *)(param_2 + 0x2fc) * FLOAT_803e27bc;
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x5b8) {
    if (*(char *)(iVar4 + 0x27) != '\0') {
      *(undefined2 *)(param_2 + 0x2b6) = 0x5fe;
    }
    *(float *)(param_2 + 0x2ac) = FLOAT_803e27c0;
    *(undefined2 *)(param_2 + 0x2b0) = 0x3c;
    *(undefined *)(param_2 + 0x33b) = 4;
  }
  else if (sVar1 < 0x5b8) {
    if (sVar1 == 0x13a) {
      if (*(char *)(iVar4 + 0x27) != '\0') {
        *(undefined2 *)(param_2 + 0x2b6) = 0x33;
      }
      *(float *)(param_2 + 0x2ac) = FLOAT_803e27c0;
      *(undefined2 *)(param_2 + 0x2b0) = 0x28;
      *(undefined *)(param_2 + 0x33b) = 0;
    }
    else if (sVar1 < 0x13a) {
      if (sVar1 == 0x11) {
        if (*(char *)(iVar4 + 0x27) != '\0') {
          *(undefined2 *)(param_2 + 0x2b6) = 0x33;
        }
        *(float *)(param_2 + 0x2ac) = FLOAT_803e27c0;
        *(undefined2 *)(param_2 + 0x2b0) = 0x28;
        *(undefined *)(param_2 + 0x33b) = 1;
      }
    }
    else if (0x5b6 < sVar1) {
      if (*(char *)(iVar4 + 0x27) != '\0') {
        *(undefined2 *)(param_2 + 0x2b6) = 0x5fa;
      }
      *(float *)(param_2 + 0x2ac) = FLOAT_803e27c4;
      *(undefined2 *)(param_2 + 0x2b0) = 0x32;
      *(undefined *)(param_2 + 0x33b) = 3;
    }
  }
  else if (sVar1 == 0x5e1) {
    if (*(char *)(iVar4 + 0x27) != '\0') {
      *(undefined2 *)(param_2 + 0x2b6) = 0x5f9;
    }
    *(float *)(param_2 + 0x2ac) = FLOAT_803e27c0;
    *(undefined2 *)(param_2 + 0x2b0) = 0x32;
    *(undefined *)(param_2 + 0x33b) = 2;
  }
  else if (sVar1 < 0x5e1) {
    if (sVar1 < 0x5ba) {
      if (*(char *)(iVar4 + 0x27) != '\0') {
        *(undefined2 *)(param_2 + 0x2b6) = 0x33;
      }
      *(float *)(param_2 + 0x2ac) = FLOAT_803e27c0;
      *(undefined2 *)(param_2 + 0x2b0) = 1;
      *(undefined *)(param_2 + 0x33b) = 1;
    }
  }
  else if (sVar1 == 0x7a6) {
    if (*(char *)(iVar4 + 0x27) != '\0') {
      *(undefined2 *)(param_2 + 0x2b6) = 0x7a5;
    }
    *(float *)(param_2 + 0x2ac) = FLOAT_803e27c0;
    *(undefined2 *)(param_2 + 0x2b0) = 0xa0;
    *(undefined *)(param_2 + 0x33b) = 5;
    *(undefined *)(param_2 + 800) = 0;
    fVar2 = FLOAT_803e2748;
    *(float *)(param_2 + 0x314) = FLOAT_803e2748;
    *(undefined *)(param_2 + 0x321) = 0x15;
    *(float *)(param_2 + 0x318) = FLOAT_803e27b8;
    *(undefined *)(param_2 + 0x322) = 0;
    *(float *)(param_2 + 0x31c) = fVar2;
    uVar3 = FUN_80026cfc(&DAT_803dbc98,1);
    *(undefined4 *)(param_2 + 0x36c) = uVar3;
    FUN_80026c38((double)FLOAT_803e27c8,(double)FLOAT_803e27cc,(double)FLOAT_803e27d0,
                 *(undefined4 *)(param_2 + 0x36c));
    *(code **)(param_1 + 0x108) = FUN_8014d0f0;
    FUN_80026c30(*(undefined4 *)(param_2 + 0x36c),1);
  }
  if (*(char *)(iVar4 + 0x2e) != -1) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 1;
  }
  return;
}

