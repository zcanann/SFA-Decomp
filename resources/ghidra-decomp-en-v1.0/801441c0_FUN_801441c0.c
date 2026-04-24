// Function: FUN_801441c0
// Entry: 801441c0
// Size: 740 bytes

/* WARNING: Removing unreachable block (ram,0x80144484) */

void FUN_801441c0(void)

{
  short *psVar1;
  int iVar2;
  int iVar3;
  short sVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined8 uVar11;
  float local_38 [2];
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar11 = FUN_802860dc();
  psVar1 = (short *)((ulonglong)uVar11 >> 0x20);
  iVar5 = (int)uVar11;
  uVar7 = 1;
  uVar6 = 3;
  local_38[0] = FLOAT_803e2524;
  iVar2 = FUN_80036e58(0x4d,psVar1,local_38);
  if ((iVar2 != 0) && ((*(ushort *)(iVar2 + 0xb0) & 0x800) != 0)) {
    uVar7 = 0;
  }
  iVar3 = (**(code **)(*DAT_803dca58 + 0x24))(0);
  if ((iVar3 == 0) || (iVar3 = FUN_8001ffb4(0xdd), iVar3 == 0)) {
    uVar6 = 2;
  }
  iVar3 = FUN_800221a0(uVar7,uVar6);
  if (iVar3 == 2) {
    FUN_8013a3f0((double)FLOAT_803e2530,psVar1,0x2d,0);
    *(uint *)(iVar5 + 0x54) = *(uint *)(iVar5 + 0x54) | 0x10;
    *(undefined *)(iVar5 + 10) = 9;
  }
  else if (iVar3 < 2) {
    if (iVar3 == 0) {
      *(int *)(iVar5 + 0x24) = iVar2;
      FUN_80039510(iVar2,0,iVar5 + 0x72c);
      if (*(int *)(iVar5 + 0x28) != iVar5 + 0x72c) {
        *(int *)(iVar5 + 0x28) = iVar5 + 0x72c;
        *(uint *)(iVar5 + 0x54) = *(uint *)(iVar5 + 0x54) & 0xfffffbff;
        *(undefined2 *)(iVar5 + 0xd2) = 0;
      }
      *(byte *)(iVar5 + 0x728) = *(byte *)(iVar5 + 0x728) & 0xdf;
      *(undefined *)(iVar5 + 10) = 0xc;
    }
    else if (-1 < iVar3) {
      sVar4 = FUN_800221a0(0x20,0xff);
      uStack44 = (int)(short)((*psVar1 + sVar4) * 0x100) ^ 0x80000000;
      local_30 = 0x43300000;
      dVar10 = (double)((FLOAT_803e2454 *
                        (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e2460)) /
                       FLOAT_803e2458);
      dVar9 = (double)FUN_80293e80(dVar10);
      *(float *)(iVar5 + 0x72c) = (float)(DOUBLE_803e2528 * -dVar9 + (double)*(float *)(psVar1 + 6))
      ;
      *(undefined4 *)(iVar5 + 0x730) = *(undefined4 *)(psVar1 + 8);
      dVar9 = (double)FUN_80294204(dVar10);
      *(float *)(iVar5 + 0x734) =
           (float)((double)FLOAT_803e2484 * -dVar9 + (double)*(float *)(psVar1 + 10));
      if (*(int *)(iVar5 + 0x28) != iVar5 + 0x72c) {
        *(int *)(iVar5 + 0x28) = iVar5 + 0x72c;
        *(uint *)(iVar5 + 0x54) = *(uint *)(iVar5 + 0x54) & 0xfffffbff;
        *(undefined2 *)(iVar5 + 0xd2) = 0;
      }
      *(undefined *)(iVar5 + 10) = 8;
    }
  }
  else if (iVar3 < 4) {
    FUN_8013a3f0((double)FLOAT_803e2444,psVar1,0x29,0);
    iVar2 = *(int *)(psVar1 + 0x5c);
    if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < psVar1[0x50] || (psVar1[0x50] < 0x29)) &&
        (iVar3 = FUN_8000b578(psVar1,0x10), iVar3 == 0)))) {
      FUN_800393f8(psVar1,iVar2 + 0x3a8,0x354,0x1000,0xffffffff,0);
    }
    *(uint *)(iVar5 + 0x54) = *(uint *)(iVar5 + 0x54) | 0x10;
    *(undefined *)(iVar5 + 10) = 4;
    uStack44 = FUN_800221a0(0x78,0xf0);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    *(float *)(iVar5 + 0x73c) = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e2460);
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286128();
  return;
}

