// Function: FUN_802077c4
// Entry: 802077c4
// Size: 992 bytes

/* WARNING: Removing unreachable block (ram,0x80207b84) */
/* WARNING: Removing unreachable block (ram,0x80207b7c) */
/* WARNING: Removing unreachable block (ram,0x80207b74) */
/* WARNING: Removing unreachable block (ram,0x802077e4) */
/* WARNING: Removing unreachable block (ram,0x802077dc) */
/* WARNING: Removing unreachable block (ram,0x802077d4) */

void FUN_802077c4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  char cVar5;
  char cVar6;
  char cVar7;
  int iVar8;
  short *psVar9;
  double dVar10;
  undefined8 uVar11;
  double in_f29;
  double dVar12;
  double in_f30;
  double dVar13;
  double in_f31;
  double dVar14;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined2 local_78;
  undefined2 local_76;
  undefined2 local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  undefined4 local_60;
  uint uStack_5c;
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
  uVar2 = FUN_80286838();
  psVar9 = *(short **)(uVar2 + 0xb8);
  iVar3 = FUN_8002bac4();
  iVar8 = 0;
  cVar7 = '\0';
  cVar6 = '\0';
  cVar5 = '\0';
  dVar14 = (double)(*(float *)(iVar3 + 0xc) - *(float *)(uVar2 + 0xc));
  dVar12 = (double)(*(float *)(iVar3 + 0x10) - *(float *)(uVar2 + 0x10));
  dVar10 = (double)*(float *)(iVar3 + 0x14);
  dVar13 = (double)(float)(dVar10 - (double)*(float *)(uVar2 + 0x14));
  if (((int)psVar9[4] == 0xffffffff) || (uVar4 = FUN_80020078((int)psVar9[4]), uVar4 == 0)) {
    uVar4 = FUN_80020078((int)psVar9[5]);
    if (uVar4 != 0) {
      dVar10 = (double)FUN_800201ac((int)psVar9[5],0);
    }
    if (dVar14 <= (double)FLOAT_803e70d0) {
      uStack_5c = (int)*psVar9 ^ 0x80000000;
      local_60 = 0x43300000;
      dVar10 = DOUBLE_803e70d8;
      if (-(double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e70d8) < dVar14) {
        iVar8 = 1;
        cVar7 = '\x01';
      }
    }
    if ((double)FLOAT_803e70d0 < dVar14) {
      uStack_5c = (int)*psVar9 ^ 0x80000000;
      local_60 = 0x43300000;
      dVar10 = DOUBLE_803e70d8;
      if (dVar14 < (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e70d8)) {
        iVar8 = iVar8 + 1;
        cVar7 = cVar7 + -1;
      }
    }
    if (dVar13 <= (double)FLOAT_803e70d0) {
      uStack_5c = (int)psVar9[1] ^ 0x80000000;
      local_60 = 0x43300000;
      dVar10 = DOUBLE_803e70d8;
      if (-(double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e70d8) < dVar13) {
        iVar8 = iVar8 + 1;
        cVar5 = '\x01';
      }
    }
    if ((double)FLOAT_803e70d0 < dVar13) {
      uStack_5c = (int)psVar9[1] ^ 0x80000000;
      local_60 = 0x43300000;
      dVar10 = DOUBLE_803e70d8;
      if (dVar13 < (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e70d8)) {
        iVar8 = iVar8 + 1;
        cVar5 = cVar5 + -1;
      }
    }
    if (dVar12 <= (double)FLOAT_803e70d0) {
      uStack_5c = (int)psVar9[2] ^ 0x80000000;
      local_60 = 0x43300000;
      dVar10 = DOUBLE_803e70d8;
      if (-(double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e70d8) < dVar12) {
        iVar8 = iVar8 + 1;
        cVar6 = '\x01';
      }
    }
    if ((double)FLOAT_803e70d0 < dVar12) {
      uStack_5c = (int)psVar9[2] ^ 0x80000000;
      local_60 = 0x43300000;
      dVar10 = DOUBLE_803e70d8;
      if (dVar12 < (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e70d8)) {
        iVar8 = iVar8 + 1;
        cVar6 = cVar6 + -1;
      }
    }
    if (iVar8 == 3) {
      local_6c = (float)dVar14;
      local_68 = (float)dVar12;
      local_64 = (float)dVar13;
      local_70 = FLOAT_803e70e0;
      local_74 = 0;
      local_76 = 0;
      local_78 = 0;
      if (cVar7 != *(char *)(psVar9 + 8)) {
        local_78 = 0x3fff;
      }
      uVar4 = FUN_80020078(0x1d9);
      if (uVar4 == 0) {
        FUN_800379bc(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x60004,
                     uVar2,1,in_r7,in_r8,in_r9,in_r10);
        (**(code **)(*DAT_803dd708 + 8))(uVar2,0x5ed,&local_78,2,0xffffffff,0);
        iVar3 = 9;
        do {
          (**(code **)(*DAT_803dd708 + 8))(uVar2,0x5fd,&local_78,2,0xffffffff,0);
          bVar1 = iVar3 != 0;
          iVar3 = iVar3 + -1;
        } while (bVar1);
      }
      else {
        uVar11 = FUN_800201ac(0x468,1);
        FUN_800379bc(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x60004,
                     uVar2,0,in_r7,in_r8,in_r9,in_r10);
        (**(code **)(*DAT_803dd708 + 8))(uVar2,0x5ed,&local_78,2,0xffffffff,0);
        iVar3 = 9;
        do {
          (**(code **)(*DAT_803dd708 + 8))(uVar2,0x5fd,&local_78,2,0xffffffff,0);
          bVar1 = iVar3 != 0;
          iVar3 = iVar3 + -1;
        } while (bVar1);
      }
      FUN_800201ac((int)psVar9[5],1);
      FUN_8000bb38(uVar2,0x1c9);
    }
    *(char *)(psVar9 + 8) = cVar7;
    *(char *)((int)psVar9 + 0x11) = cVar6;
    *(char *)(psVar9 + 9) = cVar5;
  }
  FUN_80286884();
  return;
}

