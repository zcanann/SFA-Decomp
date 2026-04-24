// Function: FUN_801dc444
// Entry: 801dc444
// Size: 324 bytes

void FUN_801dc444(int param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  *(byte *)((int)pfVar4 + 0x22) = *(byte *)((int)pfVar4 + 0x22) & 0x7f;
  *(undefined *)((int)pfVar4 + 0x1e) = 0xff;
  *(undefined *)((int)pfVar4 + 0x1d) = 0;
  *(code **)(param_1 + 0xbc) = FUN_801db688;
  FUN_800201ac(0x60f,1);
  FUN_800201ac(0x2b8,0);
  FUN_800201ac(0x4bd,1);
  FUN_800201ac(0x81,0);
  FUN_800201ac(0x82,0);
  FUN_800201ac(0x83,0);
  FUN_800201ac(0x84,0);
  pfVar4[3] = FLOAT_803e6218;
  fVar1 = FLOAT_803e61fc;
  *pfVar4 = FLOAT_803e61fc;
  pfVar4[1] = fVar1;
  pfVar4[2] = FLOAT_803e6200;
  FUN_8004c38c((double)(float)((double)FLOAT_803e6208 + (double)*pfVar4),(double)*pfVar4,
               (double)FLOAT_803e620c,(double)FLOAT_803e6210,(double)FLOAT_803e6214,0);
  uVar2 = FUN_80020078(0x7a);
  if (uVar2 != 0) {
    FUN_800201ac(0x85,1);
  }
  iVar3 = FUN_8004832c(0xe);
  FUN_80043604(iVar3,0,0);
  iVar3 = FUN_800e8a48();
  if (iVar3 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  *(undefined4 *)(param_1 + 0xf8) = 1;
  return;
}

