// Function: FUN_801d188c
// Entry: 801d188c
// Size: 704 bytes

/* WARNING: Removing unreachable block (ram,0x801d1b2c) */
/* WARNING: Removing unreachable block (ram,0x801d1b24) */
/* WARNING: Removing unreachable block (ram,0x801d1b1c) */
/* WARNING: Removing unreachable block (ram,0x801d1b14) */
/* WARNING: Removing unreachable block (ram,0x801d1b0c) */
/* WARNING: Removing unreachable block (ram,0x801d1b04) */
/* WARNING: Removing unreachable block (ram,0x801d1afc) */
/* WARNING: Removing unreachable block (ram,0x801d1af4) */
/* WARNING: Removing unreachable block (ram,0x801d1aec) */
/* WARNING: Removing unreachable block (ram,0x801d18dc) */
/* WARNING: Removing unreachable block (ram,0x801d18d4) */
/* WARNING: Removing unreachable block (ram,0x801d18cc) */
/* WARNING: Removing unreachable block (ram,0x801d18c4) */
/* WARNING: Removing unreachable block (ram,0x801d18bc) */
/* WARNING: Removing unreachable block (ram,0x801d18b4) */
/* WARNING: Removing unreachable block (ram,0x801d18ac) */
/* WARNING: Removing unreachable block (ram,0x801d18a4) */
/* WARNING: Removing unreachable block (ram,0x801d189c) */

void FUN_801d188c(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  double extraout_f1;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double in_f23;
  double dVar12;
  double in_f24;
  double in_f25;
  double dVar13;
  double in_f26;
  double in_f27;
  double dVar14;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_c0;
  int local_bc;
  float local_b8;
  undefined4 local_b0;
  uint uStack_ac;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
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
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  piVar1 = (int *)FUN_80286840();
  dVar12 = extraout_f1;
  iVar2 = FUN_80021884();
  uStack_ac = (int)(short)iVar2 ^ 0x80000000;
  local_b0 = 0x43300000;
  dVar4 = (double)FUN_802945e0();
  dVar5 = (double)FUN_80294964();
  local_c0 = -(float)(dVar12 * dVar4 - (double)(float)piVar1[3]);
  local_bc = piVar1[4];
  local_b8 = -(float)(dVar12 * dVar5 - (double)(float)piVar1[5]);
  iVar2 = FUN_80064248(piVar1 + 3,&local_c0,(float *)0x3,(int *)0x0,piVar1,8,0xffffffff,0xff,0);
  if (iVar2 != 0) {
    dVar14 = dVar4;
    dVar6 = (double)FUN_802945e0();
    dVar7 = (double)FUN_802945e0();
    dVar13 = dVar5;
    dVar8 = (double)FUN_80294964();
    dVar9 = (double)FUN_80294964();
    iVar2 = 0;
    while( true ) {
      dVar10 = (double)(float)(dVar4 * dVar8 + (double)(float)(dVar5 * dVar6));
      dVar5 = (double)(float)(dVar5 * dVar8 - (double)(float)(dVar4 * dVar6));
      local_c0 = -(float)(dVar12 * dVar10 - (double)(float)piVar1[3]);
      local_b8 = -(float)(dVar12 * dVar5 - (double)(float)piVar1[5]);
      iVar3 = FUN_80064248(piVar1 + 3,&local_c0,(float *)0x1,(int *)0x0,piVar1,8,0xffffffff,0xff,0);
      if (iVar3 == 0) break;
      dVar11 = (double)(float)(dVar14 * dVar9 + (double)(float)(dVar13 * dVar7));
      dVar13 = (double)(float)(dVar13 * dVar9 - (double)(float)(dVar14 * dVar7));
      local_c0 = -(float)(dVar12 * dVar11 - (double)(float)piVar1[3]);
      local_b8 = -(float)(dVar12 * dVar13 - (double)(float)piVar1[5]);
      iVar3 = FUN_80064248(piVar1 + 3,&local_c0,(float *)0x1,(int *)0x0,piVar1,8,0xffffffff,0xff,0);
      if ((iVar3 == 0) || (iVar2 = iVar2 + 1, dVar4 = dVar10, dVar14 = dVar11, 7 < iVar2)) break;
    }
  }
  FUN_8028688c();
  return;
}

