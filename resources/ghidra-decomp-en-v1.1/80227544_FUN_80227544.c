// Function: FUN_80227544
// Entry: 80227544
// Size: 440 bytes

void FUN_80227544(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  char cVar3;
  int iVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar4;
  double dVar5;
  undefined8 uVar6;
  undefined auStack_18 [16];
  
  pfVar4 = *(float **)(param_9 + 0xb8);
  dVar5 = (double)*pfVar4;
  if ((double)FLOAT_803e7a40 < dVar5) {
    uVar6 = FUN_80019940(0xff,0xff,0xff,0xff);
    FUN_800168a8(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x579);
    *pfVar4 = *pfVar4 - FLOAT_803dc074;
    dVar5 = (double)*pfVar4;
    if (dVar5 < (double)FLOAT_803e7a40) {
      *pfVar4 = FLOAT_803e7a40;
    }
  }
  if (*(int *)(param_9 + 0xf4) == 0) {
    uVar1 = FUN_80020078(0xe05);
    if (uVar1 == 0) {
      uVar6 = FUN_80008b74(dVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x1fb,0,in_r7,in_r8,in_r9,in_r10);
      uVar6 = FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x1ff,0,in_r7,in_r8,in_r9,in_r10);
      uVar6 = FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x1fc,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x1fd,0,in_r7,in_r8,in_r9,in_r10);
      FUN_800890e0((double)FLOAT_803e7a40,0);
      FUN_800201ac(0xe05,1);
    }
    *(undefined4 *)(param_9 + 0xf4) = 1;
  }
  cVar3 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
  if (cVar3 == '\x02') {
    FUN_80225804(param_9,(int)pfVar4);
  }
  else {
    FUN_80225ddc(param_9,(int)pfVar4);
  }
  FUN_8022739c((int)pfVar4);
  iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_18);
  if (iVar2 == 0) {
    FUN_800201ac(0x7f3,0);
    FUN_800201ac(0x7f1,1);
  }
  else {
    FUN_800201ac(0x7f3,1);
    FUN_800201ac(0x7f1,0);
  }
  return;
}

