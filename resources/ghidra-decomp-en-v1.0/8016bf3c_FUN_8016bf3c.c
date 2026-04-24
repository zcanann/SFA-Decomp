// Function: FUN_8016bf3c
// Entry: 8016bf3c
// Size: 424 bytes

void FUN_8016bf3c(int param_1)

{
  int iVar1;
  undefined auStack632 [48];
  undefined auStack584 [48];
  undefined auStack536 [48];
  undefined auStack488 [48];
  undefined auStack440 [48];
  undefined auStack392 [12];
  float local_17c;
  float local_16c;
  float local_15c;
  undefined auStack344 [48];
  undefined auStack296 [48];
  undefined auStack248 [48];
  undefined auStack200 [48];
  undefined auStack152 [48];
  undefined auStack104 [48];
  undefined auStack56 [48];
  
  if ((*(byte *)(*(int *)(param_1 + 0xb8) + 0x7f) & 4) == 0) {
    FUN_8003b8f4((double)FLOAT_803e3228);
  }
  else {
    FUN_8002b47c(param_1,auStack56,0);
    iVar1 = *(int *)(param_1 + 0x4c);
    FUN_802472e4(-(double)(*(float *)(iVar1 + 8) - FLOAT_803dcdd8),-(double)*(float *)(iVar1 + 0xc),
                 -(double)(*(float *)(iVar1 + 0x10) - FLOAT_803dcddc),auStack104);
    FUN_80246eb4(auStack104,auStack56,auStack152);
    iVar1 = (**(code **)(*DAT_803dca50 + 0xc))();
    *(short *)(iVar1 + 2) = *(short *)(iVar1 + 2) + -0x8000;
    *(float *)(iVar1 + 8) = FLOAT_803e3228;
    FUN_8002b47c(iVar1,auStack392,0);
    *(short *)(iVar1 + 2) = *(short *)(iVar1 + 2) + -0x8000;
    *(float *)(iVar1 + 8) = FLOAT_803e322c;
    FUN_802472e4(-(double)local_17c,-(double)local_16c,-(double)local_15c,auStack200);
    FUN_802470c8((double)FLOAT_803e3230,auStack248,0x79);
    FUN_802470c8((double)FLOAT_803e3230,auStack296,0x7a);
    FUN_802472e4((double)local_17c,(double)local_16c,(double)local_15c,auStack344);
    FUN_80246eb4(auStack200,auStack392,auStack440);
    FUN_80246eb4(auStack248,auStack440,auStack488);
    FUN_80246eb4(auStack296,auStack488,auStack536);
    FUN_80246eb4(auStack344,auStack536,auStack584);
    FUN_80246eb4(auStack584,auStack152,auStack632);
    FUN_800412d4(auStack632);
    FUN_80041ac4(param_1);
  }
  return;
}

