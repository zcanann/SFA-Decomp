// Function: FUN_801287ac
// Entry: 801287ac
// Size: 1548 bytes

/* WARNING: Removing unreachable block (ram,0x80128d98) */
/* WARNING: Removing unreachable block (ram,0x801287bc) */

void FUN_801287ac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  char cVar2;
  short sVar3;
  undefined4 uVar4;
  undefined *puVar5;
  ushort uVar7;
  uint uVar6;
  uint uVar8;
  int iVar9;
  byte bVar11;
  uint uVar10;
  short sVar12;
  int iVar13;
  double dVar14;
  undefined8 uVar15;
  double in_f31;
  double dVar16;
  double in_ps31_1;
  int local_e8;
  int local_e4;
  int iStack_e0;
  int aiStack_dc [3];
  longlong local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  longlong local_b8;
  undefined4 local_b0;
  uint uStack_ac;
  undefined4 local_a8;
  uint uStack_a4;
  longlong local_a0;
  undefined4 local_98;
  uint uStack_94;
  undefined4 local_90;
  uint uStack_8c;
  longlong local_88;
  longlong local_80;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar4 = FUN_80286838();
  FUN_8001b4f8(FUN_8011e974);
  FLOAT_803dc6f4 = FLOAT_803e2d20;
  if (FLOAT_803e2abc < FLOAT_803de43c) {
    bVar11 = 0;
    for (puVar5 = DAT_803de4a4; -1 < *(int *)(puVar5 + 0x18); puVar5 = puVar5 + 0x20) {
      bVar11 = bVar11 + 1;
    }
    while (bVar11 = bVar11 - 1, -1 < (char)bVar11) {
      if ((int)(char)bVar11 != DAT_803de458) {
        FUN_80128db8((uint)bVar11,uVar4,0);
      }
    }
  }
  else {
    bVar11 = 0;
    for (iVar9 = 0; -1 < *(int *)(DAT_803de4a4 + iVar9 + 0x18); iVar9 = iVar9 + 0x20) {
      if ((int)(char)bVar11 != DAT_803de458) {
        FUN_80128db8((uint)bVar11,uVar4,0);
      }
      bVar11 = bVar11 + 1;
    }
  }
  FUN_80128db8(DAT_803de458 & 0xff,uVar4,0);
  dVar16 = (double)FLOAT_803dc728;
  dVar14 = (double)FUN_802945e0();
  dVar14 = (double)(float)(dVar16 * dVar14 + dVar16);
  aiStack_dc[2] = (int)(short)uVar4 ^ 0x80000000;
  aiStack_dc[1] = 0x43300000;
  iVar9 = (int)((double)(float)((double)CONCAT44(0x43300000,aiStack_dc[2]) - DOUBLE_803e2af8) *
               dVar14);
  local_d0 = (longlong)iVar9;
  FUN_80128db8(DAT_803de458 & 0xff,iVar9,4);
  iVar13 = (int)(short)uVar4;
  local_c8 = (double)CONCAT44(0x43300000,iVar13 * (0x200 - DAT_803de3dc) ^ 0x80000000);
  iVar9 = (int)((local_c8 - DOUBLE_803e2af8) * DOUBLE_803e2d08);
  local_c0 = (double)(longlong)iVar9;
  uVar15 = FUN_80019940(0xff,0xff,0xff,(byte)iVar9);
  DAT_803dc6f2 = 0x100 - DAT_803de3dc;
  if ((DAT_803de400 < 0xb) && (7 < DAT_803de400)) {
    FUN_80016848(uVar15,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,1000,200,0x154);
  }
  else {
    FUN_80016848(uVar15,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,0x3dd,200,0x154);
  }
  if (DAT_803de3dc != 0) {
    local_c0 = (double)CONCAT44(0x43300000,iVar13 * DAT_803de3dc ^ 0x80000000);
    iVar9 = (int)((local_c0 - DOUBLE_803e2af8) * DOUBLE_803e2d08);
    local_c8 = (double)(longlong)iVar9;
    uVar15 = FUN_80019940(0xff,0xff,0xff,(byte)iVar9);
    DAT_803dc6f2 = DAT_803de3dc + -0xff;
    if (DAT_803de4a4 == &DAT_8031c468) {
      uVar15 = FUN_800162c4(*(uint *)(DAT_803de458 * 0x20 + -0x7fce3b84),0,0,aiStack_dc,&iStack_e0,
                            &local_e4,&local_e8);
      sVar3 = 0xdc - (short)((local_e8 - local_e4) / 2);
    }
    else {
      sVar3 = 0xdc;
    }
    uVar15 = FUN_80016848(uVar15,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,
                          *(undefined4 *)(DAT_803de4a4 + DAT_803de458 * 0x20 + 0x14),200,(int)sVar3)
    ;
    FUN_80016848(uVar15,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,0x3de,200,0x154);
  }
  if (DAT_803de3dc == 0) {
    local_c0 = (double)(longlong)(int)FLOAT_803e2bb4;
    local_c8 = (double)CONCAT44(0x43300000,(uint)(byte)DAT_803de4a4[DAT_803de458 * 0x20 + 8]);
    uStack_a4 = (uint)((float)(DOUBLE_803e2d98 *
                              (double)*(float *)(DAT_803de4a4 + DAT_803de458 * 0x20 + 0x10)) *
                      (float)(local_c8 - DOUBLE_803e2b08));
    local_d0 = (longlong)(int)uStack_a4;
    aiStack_dc[2] = (int)(byte)DAT_803de4a4[DAT_803de458 * 0x20 + 9];
    aiStack_dc[1] = 0x43300000;
    uStack_8c = (uint)((float)(DOUBLE_803e2d98 *
                              (double)*(float *)(DAT_803de4a4 + DAT_803de458 * 0x20 + 0x10)) *
                      (float)((double)CONCAT44(0x43300000,aiStack_dc[2]) - DOUBLE_803e2b08));
    local_b8 = (longlong)(int)uStack_8c;
    uStack_ac = (uint)*(ushort *)(DAT_803de4a4 + DAT_803de458 * 0x20 + 2) +
                (int)(char)DAT_803de4a4[DAT_803de458 * 0x20 + 0xb] ^ 0x80000000;
    local_b0 = 0x43300000;
    uStack_a4 = uStack_a4 & 0xff;
    local_a8 = 0x43300000;
    iVar9 = (int)(((float)((double)CONCAT44(0x43300000,uStack_ac) - DOUBLE_803e2af8) -
                  FLOAT_803e2da0) -
                 (float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803e2b08));
    local_a0 = (longlong)iVar9;
    uVar10 = (uint)(short)((short)uStack_a4 +
                          (short)((uint)*(ushort *)(DAT_803de4a4 + DAT_803de458 * 0x20 + 2) +
                                 (int)(char)DAT_803de4a4[DAT_803de458 * 0x20 + 0xb]));
    uStack_94 = (uint)*(ushort *)(DAT_803de4a4 + DAT_803de458 * 0x20 + 4);
    local_98 = 0x43300000;
    uStack_8c = uStack_8c & 0xff;
    local_90 = 0x43300000;
    iVar1 = (int)(((float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e2b08) -
                  FLOAT_803e2da4) -
                 (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e2b08));
    local_88 = (longlong)iVar1;
    uVar8 = (uint)(short)((short)uStack_8c + *(ushort *)(DAT_803de4a4 + DAT_803de458 * 0x20 + 4));
    uVar6 = (uint)FLOAT_803de3c8;
    local_80 = (longlong)(int)uVar6;
    uVar7 = (ushort)uVar6 & 0x3f;
    if ((uVar6 & 0x20) != 0) {
      uVar7 = uVar7 ^ 0x3f;
    }
    uVar6 = iVar13 * 0xc0;
    iVar13 = (int)(short)uVar7 *
             (((int)uVar6 >> 8) + (uint)((int)uVar6 < 0 && (uVar6 & 0xff) != 0) + 0x40);
    iVar13 = iVar13 / 0x1f + (iVar13 >> 0x1f);
    cVar2 = (char)iVar13 - (char)(iVar13 >> 0x1f);
    sVar12 = (short)iVar9;
    uStack_74 = (int)sVar12 ^ 0x80000000;
    local_78 = 0x43300000;
    sVar3 = (short)iVar1;
    uStack_6c = (int)sVar3 ^ 0x80000000;
    local_70 = 0x43300000;
    uVar6 = (int)FLOAT_803e2bb4 & 0xffff;
    FUN_8011f088((double)(float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e2af8),
                 (double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e2af8),
                 DAT_803a9690,0x100,cVar2,uVar6,0);
    uStack_64 = uVar10 ^ 0x80000000;
    local_68 = 0x43300000;
    uStack_5c = (int)sVar3 ^ 0x80000000;
    local_60 = 0x43300000;
    FUN_8011ee20((double)(float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e2af8),
                 (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e2af8),
                 DAT_803a9690,0x100,cVar2,uVar6,0x12,10,1);
    uStack_54 = (int)sVar12 ^ 0x80000000;
    local_58 = 0x43300000;
    uStack_4c = uVar8 ^ 0x80000000;
    local_50 = 0x43300000;
    FUN_8011ee20((double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e2af8),
                 (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e2af8),
                 DAT_803a9690,0x100,cVar2,uVar6,0x12,10,2);
    uStack_44 = uVar10 ^ 0x80000000;
    local_48 = 0x43300000;
    uStack_3c = uVar8 ^ 0x80000000;
    local_40 = 0x43300000;
    FUN_8011ee20((double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e2af8),
                 (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e2af8),
                 DAT_803a9690,0x100,cVar2,uVar6,0x12,10,3);
  }
  FUN_8001b4f8(0);
  FUN_80286884();
  return;
}

