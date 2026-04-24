// Function: FUN_801dbe54
// Entry: 801dbe54
// Size: 324 bytes

void FUN_801dbe54(int param_1)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  *(byte *)((int)pfVar4 + 0x22) = *(byte *)((int)pfVar4 + 0x22) & 0x7f;
  *(undefined *)((int)pfVar4 + 0x1e) = 0xff;
  *(undefined *)((int)pfVar4 + 0x1d) = 0;
  *(code **)(param_1 + 0xbc) = FUN_801db098;
  FUN_800200e8(0x60f,1);
  FUN_800200e8(0x2b8,0);
  FUN_800200e8(0x4bd,1);
  FUN_800200e8(0x81,0);
  FUN_800200e8(0x82,0);
  FUN_800200e8(0x83,0);
  FUN_800200e8(0x84,0);
  pfVar4[3] = FLOAT_803e5580;
  fVar1 = FLOAT_803e5564;
  *pfVar4 = FLOAT_803e5564;
  pfVar4[1] = fVar1;
  pfVar4[2] = FLOAT_803e5568;
  FUN_8004c210((double)(float)((double)FLOAT_803e5570 + (double)*pfVar4),(double)*pfVar4,
               (double)FLOAT_803e5574,(double)FLOAT_803e5578,(double)FLOAT_803e557c,0);
  iVar2 = FUN_8001ffb4(0x7a);
  if (iVar2 != 0) {
    FUN_800200e8(0x85,1);
  }
  uVar3 = FUN_800481b0(0xe);
  FUN_8004350c(uVar3,0,0);
  iVar2 = FUN_800e87c4();
  if (iVar2 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  *(undefined4 *)(param_1 + 0xf8) = 1;
  return;
}

