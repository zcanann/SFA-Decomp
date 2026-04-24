// Function: FUN_801abf48
// Entry: 801abf48
// Size: 212 bytes

void FUN_801abf48(int param_1)

{
  int iVar1;
  uint uVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_801aba84;
  FUN_80088870(&DAT_80323580,&DAT_80323548,&DAT_803235b8,&DAT_803235f0);
  iVar1 = FUN_800e87c4();
  if (iVar1 == 0) {
    FUN_800887f8(0x1f);
    FUN_80008cbc(0,0,0x242,0);
  }
  else {
    FUN_800887f8(0x3f);
    FUN_80008b74(0,0,0x242,0);
  }
  *pfVar3 = FLOAT_803e46d4;
  pfVar3[2] = -NAN;
  uVar2 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  pfVar3[3] = (float)(uVar2 & 0xff);
  return;
}

