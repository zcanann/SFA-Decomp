// Function: FUN_8005e4c4
// Entry: 8005e4c4
// Size: 532 bytes

/* WARNING: Removing unreachable block (ram,0x8005e6bc) */
/* WARNING: Removing unreachable block (ram,0x8005e6b4) */
/* WARNING: Removing unreachable block (ram,0x8005e6ac) */
/* WARNING: Removing unreachable block (ram,0x8005e6a4) */
/* WARNING: Removing unreachable block (ram,0x8005e4ec) */
/* WARNING: Removing unreachable block (ram,0x8005e4e4) */
/* WARNING: Removing unreachable block (ram,0x8005e4dc) */
/* WARNING: Removing unreachable block (ram,0x8005e4d4) */

void FUN_8005e4c4(undefined4 param_1,undefined4 param_2,int *param_3,float *param_4)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  double in_f28;
  double dVar7;
  double in_f29;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  int local_b8;
  undefined4 uStack_b4;
  float local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  float local_a0;
  undefined4 local_9c;
  float afStack_98 [12];
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
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
  uVar11 = FUN_8028683c();
  uVar5 = param_3[4];
  uVar3 = *(undefined *)(*param_3 + ((int)uVar5 >> 3));
  iVar4 = *param_3 + ((int)uVar5 >> 3);
  uVar1 = *(undefined *)(iVar4 + 1);
  uVar2 = *(undefined *)(iVar4 + 2);
  param_3[4] = uVar5 + 8;
  puVar6 = (undefined4 *)
           (*(int *)((int)((ulonglong)uVar11 >> 0x20) + 0x68) +
           ((uint3)(CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar5 & 7)) & 0xff) * 0x1c);
  uVar5 = *(uint *)((int)uVar11 + 0x3c);
  if ((uVar5 & 0x4000) == 0) {
    if ((uVar5 & 0x8000) == 0) {
      if ((uVar5 & 0x10000) == 0) goto LAB_8005e6a4;
      iVar4 = 0x10;
    }
    else {
      iVar4 = 8;
    }
  }
  else {
    iVar4 = 4;
  }
  dVar7 = (double)FLOAT_803df8ac;
  dVar9 = (double)FLOAT_803df8a4;
  dVar10 = (double)FLOAT_803df87c;
  dVar8 = DOUBLE_803df840;
  for (uVar5 = 0; (int)uVar5 < iVar4; uVar5 = uVar5 + 1) {
    uStack_64 = uVar5 + 1 ^ 0x80000000;
    local_68 = 0x43300000;
    FUN_80247a48((double)FLOAT_803df84c,
                 (double)(float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack_64) -
                                                        dVar8)),(double)FLOAT_803df84c,afStack_98);
    FUN_80247618(param_4,afStack_98,afStack_98);
    FUN_8025d80c(afStack_98,0);
    local_b0 = DAT_802c25c0;
    local_ac = DAT_802c25c4;
    local_a8 = DAT_802c25c8;
    local_a4 = DAT_802c25cc;
    local_a0 = (float)DAT_802c25d0;
    local_9c = DAT_802c25d4;
    FUN_8006c65c(&local_b8,&uStack_b4);
    FUN_8004c460(*(int *)(local_b8 + (uVar5 & 0xff) * 4),1);
    uStack_5c = (uVar5 & 0xff) + 1 ^ 0x80000000;
    local_60 = 0x43300000;
    local_b0 = (float)((double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c) -
                                                      dVar8) * dVar9) * dVar10);
    local_a0 = local_b0;
    FUN_8025b9e8(1,&local_b0,DAT_803dc2a4);
    FUN_8025d63c(*puVar6,(uint)*(ushort *)(puVar6 + 1));
  }
LAB_8005e6a4:
  FUN_80286888();
  return;
}

