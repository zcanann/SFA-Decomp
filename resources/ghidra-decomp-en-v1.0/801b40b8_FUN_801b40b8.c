// Function: FUN_801b40b8
// Entry: 801b40b8
// Size: 528 bytes

/* WARNING: Removing unreachable block (ram,0x801b4298) */
/* WARNING: Removing unreachable block (ram,0x801b4228) */
/* WARNING: Removing unreachable block (ram,0x801b42a0) */

void FUN_801b40b8(double param_1,double param_2,byte param_3,undefined *param_4)

{
  undefined uVar1;
  undefined uVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  dVar7 = (double)FUN_80291dd8((double)(float)((double)(float)((double)FLOAT_803e4950 * param_1) /
                                              param_2));
  sVar3 = 0xff - ((ushort)(int)(FLOAT_803ddb64 * (float)((double)FLOAT_803e4938 * dVar7)) & 0xff);
  dVar7 = (double)FUN_80291dd8((double)(float)((double)(float)((double)FLOAT_803e4954 * param_1) /
                                              param_2));
  sVar4 = 0xff - ((ushort)(int)(FLOAT_803ddb60 * (float)((double)FLOAT_803e4938 * dVar7)) & 0xff);
  dVar7 = (double)FUN_80291dd8((double)(float)(param_1 / param_2));
  sVar5 = 0xff - ((ushort)(int)(FLOAT_803ddb5c * (float)((double)FLOAT_803e4938 * dVar7)) & 0xff);
  if (sVar3 < 1) {
    sVar3 = 1;
  }
  else if (0xff < sVar3) {
    sVar3 = 0xff;
  }
  if (sVar4 < 1) {
    sVar4 = 1;
  }
  else if (0xff < sVar4) {
    sVar4 = 0xff;
  }
  if (sVar5 < 1) {
    sVar5 = 1;
  }
  else if (0xff < sVar5) {
    sVar5 = 0xff;
  }
  uVar2 = (undefined)sVar3;
  uVar1 = (undefined)sVar5;
  if (param_3 == 2) {
    *param_4 = uVar1;
    param_4[1] = uVar2;
    param_4[2] = uVar1;
  }
  else if (param_3 < 2) {
    if (param_3 == 0) {
      *param_4 = uVar2;
      param_4[1] = (char)sVar4;
      param_4[2] = uVar1;
    }
    else {
      *param_4 = uVar2;
      param_4[1] = uVar1;
      param_4[2] = uVar1;
    }
  }
  else if (param_3 < 4) {
    *param_4 = uVar1;
    param_4[1] = uVar1;
    param_4[2] = uVar2;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return;
}

