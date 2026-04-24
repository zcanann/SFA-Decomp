// Function: FUN_80112e94
// Entry: 80112e94
// Size: 680 bytes

/* WARNING: Removing unreachable block (ram,0x8011311c) */

void FUN_80112e94(undefined4 param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  short *psVar2;
  uint uVar3;
  char cVar4;
  int iVar5;
  int unaff_r29;
  int *piVar6;
  undefined4 uVar7;
  double extraout_f1;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined8 uVar10;
  char local_c0 [4];
  undefined auStack188 [8];
  undefined auStack180 [8];
  undefined4 local_ac;
  float local_a8;
  undefined4 local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  int local_94 [3];
  undefined auStack136 [128];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar10 = FUN_802860d4();
  psVar2 = (short *)((ulonglong)uVar10 >> 0x20);
  bVar1 = false;
  dVar9 = extraout_f1;
  local_94[0] = FUN_8002b9ec();
  local_94[1] = 0;
  for (piVar6 = local_94; (!bVar1 && (unaff_r29 = *piVar6, unaff_r29 != 0)); piVar6 = piVar6 + 1) {
    local_a0 = *(float *)(unaff_r29 + 0x18) - *(float *)(psVar2 + 0xc);
    local_9c = *(float *)(unaff_r29 + 0x1c) - *(float *)(psVar2 + 0xe);
    local_98 = *(float *)(unaff_r29 + 0x20) - *(float *)(psVar2 + 0x10);
    dVar8 = (double)FUN_802931a0((double)(local_98 * local_98 +
                                         local_a0 * local_a0 + local_9c * local_9c));
    if ((dVar8 < dVar9) && (*(char *)((int)uVar10 + 0x354) != '\0')) {
      dVar8 = (double)FUN_8029610c(unaff_r29);
      if ((double)FLOAT_803e1c64 < dVar8) {
        bVar1 = true;
      }
      uVar3 = FUN_800217c0(-(double)local_a0,-(double)local_98);
      if (*(short **)(psVar2 + 0x18) == (short *)0x0) {
        iVar5 = (uVar3 & 0xffff) - ((int)*psVar2 & 0xffffU);
        if (0x8000 < iVar5) {
          iVar5 = iVar5 + -0xffff;
        }
        if (iVar5 < -0x8000) {
          iVar5 = iVar5 + 0xffff;
        }
      }
      else {
        iVar5 = (uVar3 & 0xffff) - ((int)*psVar2 + (int)**(short **)(psVar2 + 0x18) & 0xffffU);
        if (0x8000 < iVar5) {
          iVar5 = iVar5 + -0xffff;
        }
        if (iVar5 < -0x8000) {
          iVar5 = iVar5 + 0xffff;
        }
      }
      if ((iVar5 < param_3) && (-param_3 < iVar5)) {
        bVar1 = true;
      }
      iVar5 = FUN_80295a04(unaff_r29,1);
      if (iVar5 == 0) {
        bVar1 = false;
      }
      iVar5 = FUN_80296ae8(unaff_r29);
      if (iVar5 < 1) {
        bVar1 = false;
      }
      else {
        local_ac = *(undefined4 *)(psVar2 + 6);
        local_a8 = FLOAT_803e1c68 + *(float *)(psVar2 + 8);
        local_a4 = *(undefined4 *)(psVar2 + 10);
        FUN_80012d00(&local_ac,auStack188);
        local_ac = *(undefined4 *)(unaff_r29 + 0xc);
        local_a8 = FLOAT_803e1c68 + *(float *)(unaff_r29 + 0x10);
        local_a4 = *(undefined4 *)(unaff_r29 + 0x14);
        FUN_80012d00(&local_ac,auStack180);
        cVar4 = FUN_800128dc(auStack180,auStack188,0,local_c0,0);
        if ((local_c0[0] == '\x01') || (cVar4 != '\0')) {
          iVar5 = FUN_800640cc((double)FLOAT_803e1c48,psVar2 + 6,&local_ac,0,auStack136,psVar2,4,
                               0xffffffff,0,0);
          if (iVar5 != 0) {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
    }
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286120(unaff_r29);
  return;
}

