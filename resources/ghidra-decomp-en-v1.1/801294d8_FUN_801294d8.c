// Function: FUN_801294d8
// Entry: 801294d8
// Size: 1276 bytes

void FUN_801294d8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  byte bVar2;
  undefined *puVar3;
  uint *puVar4;
  byte bVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  double dVar16;
  undefined8 uVar17;
  undefined auStack_e8 [32];
  longlong local_c8;
  undefined4 local_c0;
  uint uStack_bc;
  undefined4 local_b8;
  uint uStack_b4;
  undefined4 local_b0;
  uint uStack_ac;
  undefined4 local_a8;
  uint uStack_a4;
  undefined4 local_a0;
  uint uStack_9c;
  undefined4 local_98;
  uint uStack_94;
  undefined4 local_90;
  uint uStack_8c;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
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
  undefined4 local_38;
  uint uStack_34;
  
  FUN_8028682c();
  puVar3 = FUN_80017400(0x36);
  DAT_803de464 = DAT_803de464 + DAT_803dc710;
  dVar16 = (double)FUN_80293bc4();
  iVar1 = (int)((double)FLOAT_803dc714 * dVar16 + (double)FLOAT_803dc718);
  local_c8 = (longlong)iVar1;
  iVar10 = (int)*(short *)(puVar3 + 10);
  iVar12 = (int)*(short *)(puVar3 + 8);
  uVar13 = (uint)*(short *)(puVar3 + 0x16);
  uVar14 = (uint)*(short *)(puVar3 + 0x14);
  uVar8 = uVar14 - 5;
  uStack_bc = uVar8 ^ 0x80000000;
  local_c0 = 0x43300000;
  uVar9 = uVar13 - 5;
  uStack_b4 = uVar9 ^ 0x80000000;
  local_b8 = 0x43300000;
  FUN_80077318((double)(float)((double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e2af8),
               DAT_803a9638,0xff,0x100);
  uStack_ac = uVar14 ^ 0x80000000;
  local_b0 = 0x43300000;
  uStack_a4 = uVar9 ^ 0x80000000;
  local_a8 = 0x43300000;
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_ac) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803e2af8),
               DAT_803a9644,0xff,0x100,iVar12,5,0);
  uStack_9c = uVar8 ^ 0x80000000;
  local_a0 = 0x43300000;
  uStack_94 = uVar13 ^ 0x80000000;
  local_98 = 0x43300000;
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e2af8),
               DAT_803a963c,0xff,0x100,5,iVar10,0);
  uStack_8c = uVar14 ^ 0x80000000;
  local_90 = 0x43300000;
  uStack_84 = uVar13 ^ 0x80000000;
  local_88 = 0x43300000;
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e2af8),
               DAT_803a9640,0xff,0x100,iVar12,iVar10,0);
  uStack_7c = uVar14 ^ 0x80000000;
  local_80 = 0x43300000;
  uVar15 = uVar13 + iVar10;
  uStack_74 = uVar15 ^ 0x80000000;
  local_78 = 0x43300000;
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e2af8),
               DAT_803a9644,0xff,0x100,iVar12,5,2);
  uVar14 = uVar14 + iVar12;
  uStack_6c = uVar14 ^ 0x80000000;
  local_70 = 0x43300000;
  uStack_64 = uVar13 ^ 0x80000000;
  local_68 = 0x43300000;
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e2af8),
               DAT_803a963c,0xff,0x100,5,iVar10,1);
  uStack_5c = uVar14 ^ 0x80000000;
  local_60 = 0x43300000;
  uStack_54 = uVar15 ^ 0x80000000;
  local_58 = 0x43300000;
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e2af8),
               DAT_803a9638,0xff,0x100,5,5,3);
  uStack_4c = uVar14 ^ 0x80000000;
  local_50 = 0x43300000;
  uStack_44 = uVar9 ^ 0x80000000;
  local_48 = 0x43300000;
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e2af8),
               DAT_803a9638,0xff,0x100,5,5,1);
  uStack_3c = uVar8 ^ 0x80000000;
  local_40 = 0x43300000;
  uStack_34 = uVar15 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar16 = (double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e2af8);
  uVar6 = 5;
  uVar7 = 2;
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e2af8),dVar16,
               DAT_803a9638,0xff,0x100,5,5,2);
  iVar10 = 0xff;
  uVar17 = FUN_80019940(0xff,0xff,0xff,0xff);
  uVar17 = FUN_80016848(uVar17,dVar16,param_3,param_4,param_5,param_6,param_7,param_8,0x345,0,10);
  uVar17 = FUN_80016848(uVar17,dVar16,param_3,param_4,param_5,param_6,param_7,param_8,
                        (uint)*(ushort *)(&DAT_8031bb52 + (char)DAT_803dc6f8 * 4),0,0x28);
  for (uVar8 = 0; (uVar8 & 0xff) < 5; uVar8 = uVar8 + 1) {
    puVar4 = (uint *)FUN_800e8b10((uint)DAT_803dc6f8,uVar8);
    bVar2 = *(byte *)((int)puVar4 + 3);
    FUN_8028fde8(uVar17,dVar16,param_3,param_4,param_5,param_6,param_7,param_8,(int)auStack_e8,
                 &DAT_803dc808,*puVar4 >> 1,iVar10,uVar6,uVar7,in_r9,in_r10);
    if ((uVar8 & 0xff) == (uint)DAT_803dc6f9) {
      bVar5 = (byte)iVar1;
      FUN_80019940(bVar5,bVar5,bVar5,0xff);
    }
    else if ((uVar8 & 0xff) == DAT_803dc6f9 + 1) {
      FUN_80019940(0xff,0xff,0xff,0xff);
    }
    iVar11 = (uVar8 & 0xff) * 0x1e;
    iVar12 = iVar11 + 0x5a;
    FUN_80015e00(puVar4 + 1,0x86,0,iVar12);
    iVar10 = iVar12;
    uVar17 = FUN_80015e00(auStack_e8,0x87,0,iVar12);
    if ((bVar2 & 1) != 0) {
      puVar3 = FUN_80017400(0x87);
      uStack_34 = (int)*(short *)(puVar3 + 0x14) + 100U ^ 0x80000000;
      local_38 = 0x43300000;
      uStack_3c = *(short *)(puVar3 + 0x16) + iVar11 + 0x57U ^ 0x80000000;
      local_40 = 0x43300000;
      dVar16 = (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e2af8);
      FUN_80077318((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e2af8),dVar16,
                   DAT_803a9708,0xff,0x100);
      uVar17 = FUN_80015e00(&DAT_803dc810,0x87,0x82,iVar12);
      iVar10 = iVar12;
    }
  }
  FUN_80016848(uVar17,dVar16,param_3,param_4,param_5,param_6,param_7,param_8,0x346,0,0x104);
  FUN_80286878();
  return;
}

