// Function: FUN_8015a924
// Entry: 8015a924
// Size: 728 bytes

/* WARNING: Removing unreachable block (ram,0x8015abd8) */

void FUN_8015a924(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  short sVar3;
  undefined *puVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  puVar4 = (&PTR_DAT_8031fd48)[(uint)*(ushort *)(param_2 + 0x338) * 2];
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6f) = 1;
  if (*(short *)(param_1 + 0xa0) == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_80035f00();
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_80035f20();
  }
  if (((*(uint *)(param_2 + 0x2dc) & 0x80000000) != 0) && (*(byte *)(param_2 + 0x33a) < 2)) {
    if ((*(short *)(param_2 + 0x338) == 0) && (iVar1 = FUN_800221a0(0,0x14), 9 < iVar1)) {
      *(undefined *)(param_2 + 0x33a) = 7;
    }
    else {
      *(undefined *)(param_2 + 0x33a) = 1;
    }
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x40000000;
  }
  if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
    *(char *)(param_2 + 0x33a) = *(char *)(param_2 + 0x33a) + '\x01';
    if ((byte)(&DAT_803dbd2c)[*(ushort *)(param_2 + 0x338)] < *(byte *)(param_2 + 0x33a)) {
      *(undefined *)(param_2 + 0x33a) = (&DAT_803dbd28)[*(ushort *)(param_2 + 0x338)];
    }
    if (*(ushort *)(param_2 + 0x2a0) < 4) {
      iVar1 = (uint)*(byte *)(param_2 + 0x33a) * 0xc;
      FUN_8014d08c((double)*(float *)(puVar4 + iVar1),param_1,param_2,puVar4[iVar1 + 8],0,0);
    }
    else {
      iVar1 = (uint)*(byte *)(param_2 + 0x33a) * 0xc;
      FUN_8014d08c((double)*(float *)(puVar4 + iVar1),param_1,param_2,puVar4[iVar1 + 9],0,0);
    }
    if (*(short *)(param_1 + 0xa0) == 9) {
      FUN_8015a52c(param_1);
    }
    else if (*(short *)(param_1 + 0xa0) == 1) {
      uVar2 = FUN_800221a0(0,*(undefined *)(param_2 + 0x33b));
      sVar3 = FUN_800221a0(0xffff8000,0x7fff);
      dVar7 = (double)((FLOAT_803e2ca0 *
                       (float)((double)CONCAT44(0x43300000,(int)sVar3 ^ 0x80000000) -
                              DOUBLE_803e2cb0)) / FLOAT_803e2ca4);
      dVar6 = (double)FUN_80293e80(dVar7);
      *(float *)(param_1 + 0xc) =
           (float)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2cb0
                                  ) * dVar6 + (double)*(float *)(*(int *)(param_1 + 0x4c) + 8));
      dVar6 = (double)FUN_80294204(dVar7);
      *(float *)(param_1 + 0x14) =
           (float)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2cb0
                                  ) * dVar6 + (double)*(float *)(*(int *)(param_1 + 0x4c) + 0x10));
      FUN_8014cf7c((double)*(float *)(*(int *)(param_2 + 0x29c) + 0xc),
                   (double)*(float *)(*(int *)(param_2 + 0x29c) + 0x14),param_1,param_2,1,0);
    }
  }
  FUN_8014cf7c((double)*(float *)(*(int *)(param_2 + 0x29c) + 0xc),
               (double)*(float *)(*(int *)(param_2 + 0x29c) + 0x14),param_1,param_2,
               (&DAT_803dbd30)[*(ushort *)(param_2 + 0x338)],0);
  FUN_8015a77c(param_1,param_2);
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

