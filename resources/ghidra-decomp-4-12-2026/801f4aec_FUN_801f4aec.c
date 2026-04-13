// Function: FUN_801f4aec
// Entry: 801f4aec
// Size: 372 bytes

void FUN_801f4aec(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  undefined8 uVar4;
  
  FUN_8002bac4();
  pfVar3 = *(float **)(param_9 + 0xb8);
  if (FLOAT_803e6b08 < *pfVar3) {
    uVar4 = FUN_80019940(0xff,0xff,0xff,0xff);
    FUN_800168a8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x42c);
    *pfVar3 = *pfVar3 - FLOAT_803dc074;
    if (*pfVar3 < FLOAT_803e6b08) {
      *pfVar3 = FLOAT_803e6b08;
    }
  }
  if (*(char *)(pfVar3 + 5) == '\0') {
    uVar1 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
    uVar1 = countLeadingZeros(6 - (uVar1 & 0xff));
    if (((uVar1 >> 5 == 0) || (iVar2 = FUN_80080490(), iVar2 == 0)) ||
       (uVar1 = FUN_80020078(0xa7f), uVar1 == 0)) {
      FUN_801d8650(pfVar3 + 4,0x10,-1,-1,0xa7f,(int *)0xa6);
      FUN_801d84c4(pfVar3 + 4,2,-1,-1,0xa7f,(int *)0xa8);
    }
    if (0x3c < (uint)pfVar3[6]) {
      FUN_801d84c4(pfVar3 + 4,1,-1,-1,0xada,(int *)0xac);
    }
    FUN_801d84c4(pfVar3 + 4,0x20,-1,-1,0xcbb,(int *)0xc4);
  }
  FUN_801f4550(param_9);
  pfVar3[6] = (float)((int)pfVar3[6] + 1);
  return;
}

