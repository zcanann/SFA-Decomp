// Function: FUN_80144548
// Entry: 80144548
// Size: 740 bytes

/* WARNING: Removing unreachable block (ram,0x8014480c) */
/* WARNING: Removing unreachable block (ram,0x80144558) */

void FUN_80144548(void)

{
  short *psVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  bool bVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  double dVar9;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar10;
  float local_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar10 = FUN_80286840();
  psVar1 = (short *)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  uVar8 = 1;
  uVar7 = 3;
  local_38[0] = FLOAT_803e31b4;
  iVar2 = FUN_80036f50(0x4d,psVar1,local_38);
  if ((iVar2 != 0) && ((*(ushort *)(iVar2 + 0xb0) & 0x800) != 0)) {
    uVar8 = 0;
  }
  iVar3 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if ((iVar3 == 0) || (uVar4 = FUN_80020078(0xdd), uVar4 == 0)) {
    uVar7 = 2;
  }
  uVar7 = FUN_80022264(uVar8,uVar7);
  if (uVar7 == 2) {
    FUN_8013a778((double)FLOAT_803e31c0,(int)psVar1,0x2d,0);
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x10;
    *(undefined *)(iVar6 + 10) = 9;
  }
  else if ((int)uVar7 < 2) {
    if (uVar7 == 0) {
      *(int *)(iVar6 + 0x24) = iVar2;
      FUN_80039608(iVar2,0,(float *)(iVar6 + 0x72c));
      if (*(int *)(iVar6 + 0x28) != iVar6 + 0x72c) {
        *(int *)(iVar6 + 0x28) = iVar6 + 0x72c;
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffffbff;
        *(undefined2 *)(iVar6 + 0xd2) = 0;
      }
      *(byte *)(iVar6 + 0x728) = *(byte *)(iVar6 + 0x728) & 0xdf;
      *(undefined *)(iVar6 + 10) = 0xc;
    }
    else if (-1 < (int)uVar7) {
      uVar7 = FUN_80022264(0x20,0xff);
      uStack_2c = (int)(short)((*psVar1 + (short)uVar7) * 0x100) ^ 0x80000000;
      local_30 = 0x43300000;
      dVar9 = (double)FUN_802945e0();
      *(float *)(iVar6 + 0x72c) = (float)(DOUBLE_803e31b8 * -dVar9 + (double)*(float *)(psVar1 + 6))
      ;
      *(undefined4 *)(iVar6 + 0x730) = *(undefined4 *)(psVar1 + 8);
      dVar9 = (double)FUN_80294964();
      *(float *)(iVar6 + 0x734) =
           (float)((double)FLOAT_803e3114 * -dVar9 + (double)*(float *)(psVar1 + 10));
      if (*(int *)(iVar6 + 0x28) != iVar6 + 0x72c) {
        *(int *)(iVar6 + 0x28) = iVar6 + 0x72c;
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffffbff;
        *(undefined2 *)(iVar6 + 0xd2) = 0;
      }
      *(undefined *)(iVar6 + 10) = 8;
    }
  }
  else if ((int)uVar7 < 4) {
    FUN_8013a778((double)FLOAT_803e30d4,(int)psVar1,0x29,0);
    iVar2 = *(int *)(psVar1 + 0x5c);
    if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < psVar1[0x50] || (psVar1[0x50] < 0x29)) &&
        (bVar5 = FUN_8000b598((int)psVar1,0x10), !bVar5)))) {
      FUN_800394f0(psVar1,iVar2 + 0x3a8,0x354,0x1000,0xffffffff,0);
    }
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x10;
    *(undefined *)(iVar6 + 10) = 4;
    uStack_2c = FUN_80022264(0x78,0xf0);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    *(float *)(iVar6 + 0x73c) = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e30f0);
  }
  FUN_8028688c();
  return;
}

