// Function: FUN_8011ef50
// Entry: 8011ef50
// Size: 768 bytes

/* WARNING: Removing unreachable block (ram,0x8011f228) */

void FUN_8011ef50(double param_1,double param_2,double param_3,double param_4,ushort param_5,
                 ushort param_6,ushort param_7)

{
  undefined4 uVar1;
  double dVar2;
  undefined8 in_f31;
  undefined auStack152 [48];
  undefined auStack104 [48];
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FLOAT_803dd818 = (float)param_1;
  FLOAT_803dd814 = (float)param_2;
  FLOAT_803dd810 = (float)param_3;
  FLOAT_803dd80c = (float)param_4;
  uStack52 = (uint)param_5;
  local_38 = 0x43300000;
  FLOAT_803dd808 =
       (FLOAT_803e1e90 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1e88)) /
       FLOAT_803e1e94;
  uStack44 = (uint)param_6;
  local_30 = 0x43300000;
  FLOAT_803dd804 =
       (FLOAT_803e1e90 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1e88)) /
       FLOAT_803e1e94;
  uStack36 = (uint)param_7;
  local_28 = 0x43300000;
  FLOAT_803dd800 =
       (FLOAT_803e1e90 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e1e88)) /
       FLOAT_803e1e94;
  FUN_802470c8(auStack104,0x79);
  FUN_802470c8((double)FLOAT_803dd804,auStack152,0x78);
  FUN_80246eb4(auStack152,auStack104,auStack104);
  FUN_802470c8((double)FLOAT_803dd808,auStack152,0x7a);
  FUN_80246eb4(auStack152,auStack104,auStack104);
  dVar2 = (double)FLOAT_803dd80c;
  FUN_80247318(dVar2,dVar2,dVar2,auStack152);
  FUN_80246eb4(auStack152,auStack104,auStack104);
  FUN_802472e4((double)FLOAT_803dd818,(double)FLOAT_803dd814,(double)FLOAT_803dd810,auStack152);
  FUN_80246eb4(auStack152,auStack104,&DAT_803a8950);
  FUN_80247318((double)FLOAT_803dbb04,-(double)FLOAT_803dbb08,(double)FLOAT_803dbb0c,auStack104);
  FUN_802472e4((double)FLOAT_803e1e98,(double)FLOAT_803e1e68,(double)FLOAT_803e1e3c,auStack152);
  FUN_80246eb4(auStack152,auStack104,auStack152);
  FUN_80246eb4(&DAT_803a8950,auStack152,&DAT_803a8830);
  FUN_802475c8((double)FLOAT_803dbaf4,(double)FLOAT_803dbaf8,(double)FLOAT_803dbafc,
               (double)FLOAT_803dbb00,&DAT_803a87f0);
  dVar2 = (double)FUN_8000fc34();
  FLOAT_803dd7fc = (float)dVar2;
  FUN_8000fc3c((double)FLOAT_803dbaf4);
  FUN_8000fb00();
  FUN_8000f458(1);
  dVar2 = (double)FLOAT_803e1e3c;
  FUN_8000f510(dVar2,dVar2,dVar2);
  FUN_8000f4e0(0x8000,0,0);
  FUN_8000f564();
  *(float *)(DAT_803dd860 + 6) = FLOAT_803dd818;
  *(float *)(DAT_803dd860 + 8) = FLOAT_803dd814;
  *(float *)(DAT_803dd860 + 10) = FLOAT_803dd810;
  *(float *)(DAT_803dd860 + 0xc) = FLOAT_803dd818;
  *(float *)(DAT_803dd860 + 0xe) = FLOAT_803dd814;
  *(float *)(DAT_803dd860 + 0x10) = FLOAT_803dd810;
  *(float *)(DAT_803dd860 + 4) = (float)param_4;
  DAT_803dd860[2] = param_5;
  DAT_803dd860[1] = param_6;
  *DAT_803dd860 = param_7;
  *(float *)(puRam803dd864 + 6) = FLOAT_803dd818;
  *(float *)(puRam803dd864 + 8) = FLOAT_803dd814;
  *(float *)(puRam803dd864 + 10) = FLOAT_803dd810;
  *(float *)(puRam803dd864 + 0xc) = FLOAT_803dd818;
  *(float *)(puRam803dd864 + 0xe) = FLOAT_803dd814;
  *(float *)(puRam803dd864 + 0x10) = FLOAT_803dd810;
  *(float *)(puRam803dd864 + 4) = (float)param_4;
  puRam803dd864[2] = param_5;
  puRam803dd864[1] = param_6;
  *puRam803dd864 = param_7;
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  return;
}

