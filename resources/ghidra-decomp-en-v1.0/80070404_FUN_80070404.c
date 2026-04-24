// Function: FUN_80070404
// Entry: 80070404
// Size: 216 bytes

/* WARNING: Removing unreachable block (ram,0x800704bc) */
/* WARNING: Removing unreachable block (ram,0x800704c4) */

void FUN_80070404(double param_1,double param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined4 local_28 [4];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  dVar5 = (double)FUN_8000fc1c();
  FLOAT_803dd038 = (float)dVar5;
  dVar5 = (double)FUN_8000fbe8();
  FLOAT_803dd034 = (float)dVar5;
  fVar1 = (float)((double)FLOAT_803deed8 * param_1);
  fVar2 = (float)((double)FLOAT_803deed8 * param_2);
  fVar3 = FLOAT_803deedc;
  if ((FLOAT_803deedc <= fVar1) && (fVar3 = fVar1, FLOAT_803deee0 < fVar1)) {
    fVar3 = FLOAT_803deee0;
  }
  fVar1 = FLOAT_803deedc;
  if ((FLOAT_803deedc <= fVar2) && (fVar1 = fVar2, FLOAT_803deee0 < fVar2)) {
    fVar1 = FLOAT_803deee0;
  }
  FLOAT_803dd024 = fVar3 * (FLOAT_803dd034 - FLOAT_803dd038) + FLOAT_803dd038;
  FLOAT_803dd020 = fVar1 * (FLOAT_803dd034 - FLOAT_803dd038) + FLOAT_803dd038;
  local_28[0] = DAT_803dd01c;
  FUN_8025c2d4(4,local_28);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  return;
}

