// Function: FUN_801ac4fc
// Entry: 801ac4fc
// Size: 212 bytes

void FUN_801ac4fc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  uint uVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar3;
  undefined8 extraout_f1;
  undefined8 uVar4;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  *(code **)(param_9 + 0xbc) = FUN_801ac038;
  FUN_80088afc(&DAT_803241c0,&DAT_80324188,&DAT_803241f8,&DAT_80324230);
  iVar1 = FUN_800e8a48();
  if (iVar1 == 0) {
    uVar4 = FUN_80088a84(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1f);
    FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x242,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  else {
    uVar4 = FUN_80088a84(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3f);
    FUN_80008b74(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x242,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  *pfVar3 = FLOAT_803e536c;
  pfVar3[2] = -NAN;
  uVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
  pfVar3[3] = (float)(uVar2 & 0xff);
  return;
}

