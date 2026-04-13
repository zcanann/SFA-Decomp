// Function: FUN_801338a4
// Entry: 801338a4
// Size: 508 bytes

/* WARNING: Removing unreachable block (ram,0x80133a88) */
/* WARNING: Removing unreachable block (ram,0x80133a80) */
/* WARNING: Removing unreachable block (ram,0x80133a78) */
/* WARNING: Removing unreachable block (ram,0x80133a70) */
/* WARNING: Removing unreachable block (ram,0x80133a68) */
/* WARNING: Removing unreachable block (ram,0x801338d4) */
/* WARNING: Removing unreachable block (ram,0x801338cc) */
/* WARNING: Removing unreachable block (ram,0x801338c4) */
/* WARNING: Removing unreachable block (ram,0x801338bc) */
/* WARNING: Removing unreachable block (ram,0x801338b4) */

void FUN_801338a4(void)

{
  double dVar1;
  double dVar2;
  double in_f27;
  double dVar3;
  double in_f28;
  double dVar4;
  double in_f29;
  double dVar5;
  double in_f30;
  double dVar6;
  double in_f31;
  double dVar7;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_74 = CONCAT31((int3)((uint)DAT_803e2e90 >> 8),(char)DAT_803de5b0);
  FLOAT_803de5cc = -(FLOAT_803e2ef0 * FLOAT_803dc074 - FLOAT_803de5cc);
  if (FLOAT_803e2eb4 < FLOAT_803de5cc) {
    FLOAT_803de5cc = FLOAT_803de5cc - FLOAT_803e2ef4;
  }
  dVar1 = (double)FUN_802945e0();
  dVar7 = (double)(float)((double)FLOAT_803e2ef8 * dVar1);
  dVar1 = (double)FUN_80294964();
  dVar6 = (double)(float)((double)FLOAT_803e2ef8 * dVar1);
  dVar1 = (double)FUN_802945e0();
  dVar5 = (double)(float)((double)FLOAT_803e2efc * dVar1);
  dVar1 = (double)FUN_80294964();
  dVar4 = (double)(float)((double)FLOAT_803e2efc * dVar1);
  dVar1 = (double)FUN_802945e0();
  dVar3 = (double)(float)((double)FLOAT_803e2efc * dVar1);
  dVar1 = (double)FUN_80294964();
  local_78 = local_74;
  dVar2 = (double)FLOAT_803e2f08;
  uStack_6c = DAT_803de5b8 + 0x32U ^ 0x80000000;
  local_70 = 0x43300000;
  local_68 = 0x43300000;
  local_60 = 0x43300000;
  uStack_64 = uStack_6c;
  uStack_5c = uStack_6c;
  FUN_80075b98((double)(float)(dVar2 - dVar7),
               (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_6c) -
                                              DOUBLE_803e2ee0) - dVar6),
               (double)(float)(dVar2 - dVar5),
               (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_6c) -
                                              DOUBLE_803e2ee0) - dVar4),
               (double)(float)(dVar2 - dVar3),
               (double)((float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e2ee0) -
                       (float)((double)FLOAT_803e2efc * dVar1)),&local_78);
  return;
}

