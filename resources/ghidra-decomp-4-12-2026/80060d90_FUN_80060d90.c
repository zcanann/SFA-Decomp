// Function: FUN_80060d90
// Entry: 80060d90
// Size: 1152 bytes

/* WARNING: Removing unreachable block (ram,0x800611f0) */
/* WARNING: Removing unreachable block (ram,0x800611e8) */
/* WARNING: Removing unreachable block (ram,0x80061128) */
/* WARNING: Removing unreachable block (ram,0x80060e84) */
/* WARNING: Removing unreachable block (ram,0x80060ed0) */
/* WARNING: Removing unreachable block (ram,0x80061114) */
/* WARNING: Removing unreachable block (ram,0x80060eb8) */
/* WARNING: Removing unreachable block (ram,0x800610b0) */
/* WARNING: Removing unreachable block (ram,0x80060e6c) */
/* WARNING: Removing unreachable block (ram,0x80061100) */
/* WARNING: Removing unreachable block (ram,0x8006109c) */
/* WARNING: Removing unreachable block (ram,0x800610d8) */
/* WARNING: Removing unreachable block (ram,0x80061088) */
/* WARNING: Removing unreachable block (ram,0x800610ec) */
/* WARNING: Removing unreachable block (ram,0x80060f1c) */
/* WARNING: Removing unreachable block (ram,0x80060eec) */
/* WARNING: Removing unreachable block (ram,0x80060da8) */
/* WARNING: Removing unreachable block (ram,0x80060da0) */
/* WARNING: Removing unreachable block (ram,0x80060ea0) */
/* WARNING: Removing unreachable block (ram,0x80060f04) */
/* WARNING: Removing unreachable block (ram,0x80060f38) */
/* WARNING: Removing unreachable block (ram,0x800610c4) */

void FUN_80060d90(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5,float *param_6,undefined4 param_7,undefined4 param_8,int param_9)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  undefined4 *puVar4;
  float *pfVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  byte bVar9;
  int iVar10;
  int *piVar11;
  int iVar12;
  double extraout_f1;
  double dVar13;
  double dVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar16;
  uint local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar16 = FUN_8028682c();
  iVar1 = (int)((ulonglong)uVar16 >> 0x20);
  iVar6 = (int)uVar16;
  dVar15 = extraout_f1;
  piVar2 = FUN_80069ac0(&local_88);
  piVar11 = piVar2 + local_88 * 6;
  iVar12 = 0;
  iVar8 = 0;
  local_88 = 0;
  iVar10 = 0;
  if (param_9 == 0) {
    bVar9 = 8;
  }
  else {
    bVar9 = 4;
  }
  for (; piVar2 < piVar11; piVar2 = piVar2 + 6) {
    iVar3 = *piVar2;
    if ((iVar3 == 0) || (iVar3 == *(int *)(iVar1 + 0x30))) {
      dVar13 = (double)*(float *)(iVar1 + 0xc);
      dVar14 = (double)*(float *)(iVar1 + 0x14);
      if (iVar3 == 0) {
        dVar13 = (double)(float)(dVar13 - dVar15);
        dVar14 = (double)(float)(dVar14 - param_2);
      }
      local_88 = (uint)*(short *)(piVar2 + 1);
      puVar4 = (undefined4 *)(param_5 + iVar8);
      while (((pfVar5 = param_6, iVar3 = iVar10, (int)local_88 < (int)*(short *)(piVar2 + 7) &&
              (iVar12 < 0x4b0)) && (iVar10 < 0xe10))) {
        iVar3 = iVar6 + local_88 * 0x4c;
        if ((bVar9 & *(byte *)(iVar3 + 0x49)) != 0) {
          *param_6 = (float)((double)((longlong)(double)*(short *)(iVar3 + 0x10) *
                                     0x3ff0000000000000) - dVar13);
          param_6[1] = (float)((double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x16)
                                       * 0x3ff0000000000000) - (double)*(float *)(iVar1 + 0x10));
          param_6[2] = (float)((double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x1c)
                                       * 0x3ff0000000000000) - dVar14);
          param_6[3] = (float)((double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x12)
                                       * 0x3ff0000000000000) - dVar13);
          param_6[4] = (float)((double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x18)
                                       * 0x3ff0000000000000) - (double)*(float *)(iVar1 + 0x10));
          param_6[5] = (float)((double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x1e)
                                       * 0x3ff0000000000000) - dVar14);
          param_6[6] = (float)((double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x14)
                                       * 0x3ff0000000000000) - dVar13);
          param_6[7] = (float)((double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x1a)
                                       * 0x3ff0000000000000) - (double)*(float *)(iVar1 + 0x10));
          param_6[8] = (float)((double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x20)
                                       * 0x3ff0000000000000) - dVar14);
          *puVar4 = *(undefined4 *)(iVar6 + local_88 * 0x4c + 4);
          puVar4[1] = *(undefined4 *)(iVar6 + local_88 * 0x4c + 8);
          puVar4[2] = *(undefined4 *)(iVar6 + local_88 * 0x4c + 0xc);
          *(undefined *)(puVar4 + 4) = *(undefined *)(iVar6 + local_88 * 0x4c + 0x49);
          param_6 = param_6 + 9;
          iVar10 = iVar10 + 3;
          puVar4 = puVar4 + 5;
          iVar12 = iVar12 + 1;
          iVar8 = iVar8 + 0x14;
        }
        local_88 = local_88 + 1;
      }
    }
    else {
      pfVar5 = (float *)piVar2[3];
      local_84 = *pfVar5;
      local_80 = pfVar5[4];
      local_7c = pfVar5[8];
      local_78 = pfVar5[0xc] - *(float *)(iVar1 + 0xc);
      local_74 = pfVar5[1];
      local_70 = pfVar5[5];
      local_6c = pfVar5[9];
      local_68 = pfVar5[0xd] - *(float *)(iVar1 + 0x10);
      local_64 = pfVar5[2];
      local_60 = pfVar5[6];
      local_5c = pfVar5[10];
      local_58 = pfVar5[0xe] - *(float *)(iVar1 + 0x14);
      local_88 = (uint)*(short *)(piVar2 + 1);
      puVar4 = (undefined4 *)(param_5 + iVar8);
      pfVar5 = param_6;
      iVar3 = iVar10;
      while ((((int)local_88 < (int)*(short *)(piVar2 + 7) && (iVar12 < 0x4b0)) && (iVar3 < 0xe10)))
      {
        iVar7 = iVar6 + local_88 * 0x4c;
        if ((bVar9 & *(byte *)(iVar7 + 0x49)) != 0) {
          *pfVar5 = (float)(double)((longlong)(double)*(short *)(iVar7 + 0x10) * 0x3ff0000000000000)
          ;
          pfVar5[1] = (float)(double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x16) *
                                     0x3ff0000000000000);
          pfVar5[2] = (float)(double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x1c) *
                                     0x3ff0000000000000);
          pfVar5[3] = (float)(double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x12) *
                                     0x3ff0000000000000);
          pfVar5[4] = (float)(double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x18) *
                                     0x3ff0000000000000);
          pfVar5[5] = (float)(double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x1e) *
                                     0x3ff0000000000000);
          pfVar5[6] = (float)(double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x14) *
                                     0x3ff0000000000000);
          pfVar5[7] = (float)(double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x1a) *
                                     0x3ff0000000000000);
          pfVar5[8] = (float)(double)((longlong)(double)*(short *)(iVar6 + local_88 * 0x4c + 0x20) *
                                     0x3ff0000000000000);
          *puVar4 = *(undefined4 *)(iVar6 + local_88 * 0x4c + 4);
          puVar4[1] = *(undefined4 *)(iVar6 + local_88 * 0x4c + 8);
          puVar4[2] = *(undefined4 *)(iVar6 + local_88 * 0x4c + 0xc);
          *(undefined *)(puVar4 + 4) = *(undefined *)(iVar6 + local_88 * 0x4c + 0x49);
          pfVar5 = pfVar5 + 9;
          iVar3 = iVar3 + 3;
          puVar4 = puVar4 + 5;
          iVar12 = iVar12 + 1;
          iVar8 = iVar8 + 0x14;
        }
        local_88 = local_88 + 1;
      }
      if (iVar10 < iVar3) {
        FUN_80247c4c(&local_84,param_6,(int)param_6,iVar3 - iVar10);
      }
    }
    param_6 = pfVar5;
    iVar10 = iVar3;
  }
  FUN_80286878();
  return;
}

