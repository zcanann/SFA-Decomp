// Function: FUN_801e89a0
// Entry: 801e89a0
// Size: 688 bytes

/* WARNING: Removing unreachable block (ram,0x801e8c30) */
/* WARNING: Removing unreachable block (ram,0x801e89b0) */

void FUN_801e89a0(void)

{
  float fVar1;
  bool bVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  byte bVar9;
  int iVar10;
  double in_f31;
  double dVar11;
  double in_ps31_1;
  float local_88;
  float local_84;
  float local_80;
  int local_7c;
  undefined8 local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar3 = FUN_80286838();
  iVar10 = *(int *)(iVar3 + 0xb8);
  bVar2 = false;
  if ((*(byte *)(iVar10 + 0xe8) >> 6 & 1) == 0) {
    FUN_80097568((double)FLOAT_803e66c8,(double)FLOAT_803e66d0,iVar3,5,1,1,0x14,0,0);
  }
  else {
    FUN_80097568((double)FLOAT_803e66c8,(double)FLOAT_803e66cc,iVar3,5,1,1,0x14,0,0);
  }
  piVar4 = (int *)FUN_8002b660(iVar3);
  iVar5 = FUN_800284e8(*piVar4,0);
  *(undefined *)(iVar5 + 0x43) = 0x7f;
  FUN_8003b9ec(iVar3);
  for (bVar9 = 0; bVar9 < 10; bVar9 = bVar9 + 1) {
    iVar5 = iVar10 + (uint)bVar9 * 4;
    if (*(float **)(iVar5 + 0x98) == (float *)0x0) {
      if ((!bVar2) && (iVar6 = FUN_80020800(), iVar6 == 0)) {
        local_88 = *(float *)(iVar3 + 0xc);
        local_84 = *(float *)(iVar3 + 0x10);
        local_80 = *(float *)(iVar3 + 0x14);
        fVar1 = FLOAT_803e66dc;
        if ((*(byte *)(iVar10 + 0xe8) >> 6 & 1) != 0) {
          fVar1 = FLOAT_803e66d8;
        }
        dVar11 = (double)fVar1;
        local_7c = iVar3;
        uVar7 = FUN_80022264(0,2000);
        local_50 = (double)CONCAT44(0x43300000,uVar7 - 1000 ^ 0x80000000);
        local_88 = (float)(dVar11 * (double)(float)(local_50 - DOUBLE_803e66f0) + (double)local_88);
        uVar7 = FUN_80022264(0,2000);
        uStack_44 = uVar7 - 1000 ^ 0x80000000;
        local_48 = 0x43300000;
        local_84 = (float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) -
                                                   DOUBLE_803e66f0) + (double)local_84);
        uVar7 = FUN_80022264(0,2000);
        uStack_3c = uVar7 - 1000 ^ 0x80000000;
        local_40 = 0x43300000;
        local_80 = (float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000,uStack_3c) -
                                                   DOUBLE_803e66f0) + (double)local_80);
        uVar8 = FUN_8008fdac((double)FLOAT_803e66e0,(double)FLOAT_803e66e4,iVar3 + 0xc,&local_88,
                             0x14,0x40,0);
        *(undefined4 *)(iVar5 + 0x98) = uVar8;
        *(float *)(iVar5 + 0xc0) = FLOAT_803e66e8;
        bVar2 = true;
      }
    }
    else {
      FUN_8008fb90(*(float **)(iVar5 + 0x98));
      iVar6 = FUN_80020800();
      if (iVar6 == 0) {
        *(float *)(iVar5 + 0xc0) = *(float *)(iVar5 + 0xc0) + FLOAT_803dc074;
        iVar6 = (int)(FLOAT_803e66d4 + *(float *)(iVar5 + 0xc0));
        local_50 = (double)(longlong)iVar6;
        *(short *)(*(int *)(iVar5 + 0x98) + 0x20) = (short)iVar6;
        if (0x14 < *(ushort *)(*(uint *)(iVar5 + 0x98) + 0x20)) {
          FUN_8008ff08(*(uint *)(iVar5 + 0x98));
          *(undefined4 *)(iVar5 + 0x98) = 0;
        }
      }
    }
  }
  FUN_80286884();
  return;
}

