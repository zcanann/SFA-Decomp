// Function: FUN_800d639c
// Entry: 800d639c
// Size: 888 bytes

/* WARNING: Removing unreachable block (ram,0x800d66f4) */
/* WARNING: Removing unreachable block (ram,0x800d66ec) */
/* WARNING: Removing unreachable block (ram,0x800d66e4) */
/* WARNING: Removing unreachable block (ram,0x800d66dc) */
/* WARNING: Removing unreachable block (ram,0x800d66d4) */
/* WARNING: Removing unreachable block (ram,0x800d66cc) */
/* WARNING: Removing unreachable block (ram,0x800d66c4) */
/* WARNING: Removing unreachable block (ram,0x800d63dc) */
/* WARNING: Removing unreachable block (ram,0x800d63d4) */
/* WARNING: Removing unreachable block (ram,0x800d63cc) */
/* WARNING: Removing unreachable block (ram,0x800d63c4) */
/* WARNING: Removing unreachable block (ram,0x800d63bc) */
/* WARNING: Removing unreachable block (ram,0x800d63b4) */
/* WARNING: Removing unreachable block (ram,0x800d63ac) */

void FUN_800d639c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  short *psVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  char cVar6;
  int unaff_r25;
  int iVar7;
  int iVar8;
  double extraout_f1;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double in_f25;
  double dVar14;
  double in_f26;
  double in_f27;
  double dVar15;
  double in_f28;
  double dVar16;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar17;
  int iStack_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_c8;
  float local_c4;
  float local_b8;
  float local_b4;
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
  uVar17 = FUN_80286828();
  psVar1 = (short *)((ulonglong)uVar17 >> 0x20);
  iVar5 = (int)uVar17;
  iVar7 = 0;
  dVar15 = (double)FLOAT_803e1168;
  dVar16 = (double)FLOAT_803e1184;
  dVar14 = extraout_f1;
  while( true ) {
    if (((int)*(uint *)(iVar5 + 0x10) < 0) ||
       (iVar2 = FUN_800d57bc(*(uint *)(iVar5 + 0x10),&iStack_e8), iVar2 == 0)) goto LAB_800d66c4;
    if (*(int *)(iVar2 + 0x20) < 0) break;
    iVar8 = 0;
    if ((-1 < *(int *)(iVar2 + 0x24)) && (*(char *)(iVar5 + 0x30) != '\0')) {
      iVar8 = 1;
    }
    iVar3 = FUN_800d5848((double)FLOAT_803e1168,(double)FLOAT_803e1168,iVar2,iVar8,&local_b8,
                         &local_c8,&local_d8,param_3 + 2U & 0xff);
    if (iVar3 == 0) goto LAB_800d66c4;
    dVar9 = FUN_80293900((double)((local_d8 - local_d4) * (local_d8 - local_d4) +
                                 (local_b8 - local_b4) * (local_b8 - local_b4) +
                                 (local_c8 - local_c4) * (local_c8 - local_c4)));
    dVar9 = (double)(*(float *)(iVar5 + 8) + (float)(dVar14 / dVar9));
    cVar6 = '\0';
    if (dVar9 < dVar15) {
      cVar6 = -1;
      dVar9 = dVar15;
    }
    if (dVar16 < dVar9) {
      cVar6 = '\x01';
      dVar9 = dVar16;
    }
    dVar10 = FUN_80010de0(dVar9,&local_b8,&local_dc);
    dVar11 = FUN_80010de0(dVar9,&local_c8,&local_e0);
    dVar12 = FUN_80010de0(dVar9,&local_d8,&local_e4);
    iVar3 = FUN_80021884();
    if ((param_4 & 0xff) == 0) {
      dVar13 = FUN_80293900((double)((float)(dVar10 - (double)*(float *)(psVar1 + 6)) *
                                     (float)(dVar10 - (double)*(float *)(psVar1 + 6)) +
                                    (float)(dVar12 - (double)*(float *)(psVar1 + 10)) *
                                    (float)(dVar12 - (double)*(float *)(psVar1 + 10))));
    }
    else {
      FUN_80293900((double)(local_dc * local_dc + local_e4 * local_e4));
      uVar4 = FUN_80021884();
      unaff_r25 = (uVar4 & 0xffff) - 0x4000;
      dVar13 = FUN_80293900((double)((float)(dVar10 - (double)*(float *)(psVar1 + 6)) *
                                     (float)(dVar10 - (double)*(float *)(psVar1 + 6)) +
                                    (float)(dVar12 - (double)*(float *)(psVar1 + 10)) *
                                    (float)(dVar12 - (double)*(float *)(psVar1 + 10))));
    }
    if (dVar14 < dVar15) {
      dVar13 = -dVar13;
    }
    if ((cVar6 != -1) || (dVar14 <= dVar13)) {
      if ((cVar6 != '\x01') || (dVar14 <= dVar13)) {
        *(float *)(iVar5 + 8) = (float)dVar9;
      }
      else {
        *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar2 + iVar8 * 4 + 0x20);
        *(float *)(iVar5 + 8) = FLOAT_803e1168;
        if ((iVar8 != 0) && (*(int *)(iVar5 + 0x10) < 0)) {
          *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar2 + 0x20);
        }
      }
    }
    else {
      *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar2 + iVar8 * 4 + 0x18);
      *(float *)(iVar5 + 8) = FLOAT_803e1188;
      if ((iVar8 != 0) && (*(int *)(iVar5 + 0x10) < 0)) {
        *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar2 + 0x18);
      }
    }
    dVar14 = (double)(float)(dVar14 - dVar13);
    *(float *)(psVar1 + 6) = (float)dVar10;
    if ((param_4 & 0xff) != 0) {
      *(float *)(psVar1 + 8) = (float)dVar11;
    }
    *(float *)(psVar1 + 10) = (float)dVar12;
    iVar7 = iVar7 + 1;
    if (2 < iVar7) {
      *psVar1 = (short)iVar3 + -0x8000;
      if ((param_4 & 0xff) != 0) {
        psVar1[1] = (short)unaff_r25;
      }
LAB_800d66c4:
      FUN_80286874();
      return;
    }
  }
  *(undefined4 *)(iVar5 + 0x10) = 0xffffffff;
  goto LAB_800d66c4;
}

