// Function: FUN_801f44b4
// Entry: 801f44b4
// Size: 372 bytes

void FUN_801f44b4(int param_1)

{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  
  FUN_8002b9ec();
  pfVar3 = *(float **)(param_1 + 0xb8);
  if (FLOAT_803e5e70 < *pfVar3) {
    FUN_80019908(0xff,0xff,0xff,0xff);
    FUN_80016870(0x42c);
    *pfVar3 = *pfVar3 - FLOAT_803db414;
    if (*pfVar3 < FLOAT_803e5e70) {
      *pfVar3 = FLOAT_803e5e70;
    }
  }
  if (*(char *)(pfVar3 + 5) == '\0') {
    uVar1 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
    uVar1 = countLeadingZeros(6 - (uVar1 & 0xff));
    if (((uVar1 >> 5 == 0) || (iVar2 = FUN_80080204(), iVar2 == 0)) ||
       (iVar2 = FUN_8001ffb4(0xa7f), iVar2 == 0)) {
      FUN_801d8060(pfVar3 + 4,0x10,0xffffffff,0xffffffff,0xa7f,0xa6);
      FUN_801d7ed4(pfVar3 + 4,2,0xffffffff,0xffffffff,0xa7f,0xa8);
    }
    if (0x3c < (uint)pfVar3[6]) {
      FUN_801d7ed4(pfVar3 + 4,1,0xffffffff,0xffffffff,0xada,0xac);
    }
    FUN_801d7ed4(pfVar3 + 4,0x20,0xffffffff,0xffffffff,0xcbb,0xc4);
  }
  FUN_801f3f18(param_1);
  pfVar3[6] = (float)((int)pfVar3[6] + 1);
  return;
}

