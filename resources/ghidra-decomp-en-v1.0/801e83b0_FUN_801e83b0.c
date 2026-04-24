// Function: FUN_801e83b0
// Entry: 801e83b0
// Size: 688 bytes

/* WARNING: Removing unreachable block (ram,0x801e8640) */

void FUN_801e83b0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  float fVar1;
  bool bVar2;
  int iVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  byte bVar8;
  int iVar9;
  undefined4 uVar10;
  undefined8 in_f31;
  double dVar11;
  undefined8 uVar12;
  float local_88;
  float local_84;
  float local_80;
  int local_7c;
  double local_50;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar12 = FUN_802860d4();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  iVar9 = *(int *)(iVar3 + 0xb8);
  bVar2 = false;
  if ((*(byte *)(iVar9 + 0xe8) >> 6 & 1) == 0) {
    FUN_800972dc((double)FLOAT_803e5a30,(double)FLOAT_803e5a38,iVar3,5,1,1,0x14,0,0);
  }
  else {
    FUN_800972dc((double)FLOAT_803e5a30,(double)FLOAT_803e5a34,iVar3,5,1,1,0x14,0,0);
  }
  puVar4 = (undefined4 *)FUN_8002b588(iVar3);
  iVar5 = FUN_80028424(*puVar4,0);
  *(undefined *)(iVar5 + 0x43) = 0x7f;
  FUN_8003b8f4((double)FLOAT_803e5a30,iVar3,(int)uVar12,param_3,param_4,param_5);
  for (bVar8 = 0; bVar8 < 10; bVar8 = bVar8 + 1) {
    iVar5 = iVar9 + (uint)bVar8 * 4;
    if (*(int *)(iVar5 + 0x98) == 0) {
      if ((!bVar2) && (iVar6 = FUN_8002073c(), iVar6 == 0)) {
        local_88 = *(float *)(iVar3 + 0xc);
        local_84 = *(float *)(iVar3 + 0x10);
        local_80 = *(float *)(iVar3 + 0x14);
        fVar1 = FLOAT_803e5a44;
        if ((*(byte *)(iVar9 + 0xe8) >> 6 & 1) != 0) {
          fVar1 = FLOAT_803e5a40;
        }
        dVar11 = (double)fVar1;
        local_7c = iVar3;
        iVar6 = FUN_800221a0(0,2000);
        local_50 = (double)CONCAT44(0x43300000,iVar6 - 1000U ^ 0x80000000);
        local_88 = (float)(dVar11 * (double)(float)(local_50 - DOUBLE_803e5a58) + (double)local_88);
        iVar6 = FUN_800221a0(0,2000);
        uStack68 = iVar6 - 1000U ^ 0x80000000;
        local_48 = 0x43300000;
        local_84 = (float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000,uStack68) -
                                                   DOUBLE_803e5a58) + (double)local_84);
        iVar6 = FUN_800221a0(0,2000);
        uStack60 = iVar6 - 1000U ^ 0x80000000;
        local_40 = 0x43300000;
        local_80 = (float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000,uStack60) -
                                                   DOUBLE_803e5a58) + (double)local_80);
        uVar7 = FUN_8008fb20((double)FLOAT_803e5a48,(double)FLOAT_803e5a4c,iVar3 + 0xc,&local_88,
                             0x14,0x40,0);
        *(undefined4 *)(iVar5 + 0x98) = uVar7;
        *(float *)(iVar5 + 0xc0) = FLOAT_803e5a50;
        bVar2 = true;
      }
    }
    else {
      FUN_8008f904();
      iVar6 = FUN_8002073c();
      if (iVar6 == 0) {
        *(float *)(iVar5 + 0xc0) = *(float *)(iVar5 + 0xc0) + FLOAT_803db414;
        iVar6 = (int)(FLOAT_803e5a3c + *(float *)(iVar5 + 0xc0));
        local_50 = (double)(longlong)iVar6;
        *(short *)(*(int *)(iVar5 + 0x98) + 0x20) = (short)iVar6;
        if (0x14 < *(ushort *)(*(int *)(iVar5 + 0x98) + 0x20)) {
          FUN_8008fc7c();
          *(undefined4 *)(iVar5 + 0x98) = 0;
        }
      }
    }
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  FUN_80286120();
  return;
}

