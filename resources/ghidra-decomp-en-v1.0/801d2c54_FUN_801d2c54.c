// Function: FUN_801d2c54
// Entry: 801d2c54
// Size: 1508 bytes

/* WARNING: Removing unreachable block (ram,0x801d2cb8) */

void FUN_801d2c54(int param_1)

{
  float fVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  float *pfVar6;
  double dVar7;
  undefined auStack72 [4];
  int local_44;
  undefined auStack64 [4];
  undefined auStack60 [12];
  float local_30;
  undefined auStack44 [4];
  float local_28 [2];
  undefined4 local_20;
  uint uStack28;
  
  FUN_8002b9ec();
  iVar2 = FUN_8002b044(param_1);
  if (iVar2 != 0) {
    return;
  }
  pfVar6 = *(float **)(param_1 + 0xb8);
  uVar4 = (uint)*(byte *)(pfVar6 + 5);
  iVar2 = uVar4 * 0xc;
  if (uVar4 == 2) {
    if ((*(byte *)((int)pfVar6 + 0x15) & 2) != 0) {
      FUN_8000bb18(param_1,0xa1);
      *(byte *)((int)pfVar6 + 0x15) = *(byte *)((int)pfVar6 + 0x15) & 0xfd;
      iVar5 = *(int *)(param_1 + 0x4c);
      *(undefined *)(param_1 + 0x36) = 0xff;
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar5 + 8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
      *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar5 + 0x10);
      *(float *)(param_1 + 8) = FLOAT_803e5358;
      pfVar6[2] = FLOAT_803e535c;
      pfVar6[1] = pfVar6[3];
      pfVar6[4] = pfVar6[1] / pfVar6[2];
      *pfVar6 = pfVar6[2];
      FUN_80036044(param_1);
    }
    if (pfVar6[1] < *(float *)(param_1 + 8)) {
      pfVar6[4] = pfVar6[4] / FLOAT_803e537c;
    }
    if (pfVar6[4] < FLOAT_803e5358) {
      pfVar6[4] = FLOAT_803e536c;
    }
    *(float *)(param_1 + 8) = pfVar6[4] * FLOAT_803db414 + *(float *)(param_1 + 8);
    fVar1 = *pfVar6 - FLOAT_803db414;
    *pfVar6 = fVar1;
    if (fVar1 < FLOAT_803e536c) {
      *(undefined *)(pfVar6 + 5) = 0;
      *(byte *)((int)pfVar6 + 0x15) = *(byte *)((int)pfVar6 + 0x15) | 2;
    }
  }
  else {
    if (uVar4 < 2) {
      if (uVar4 != 0) {
        iVar5 = *(int *)(param_1 + 0x4c);
        if ((*(byte *)((int)pfVar6 + 0x15) & 2) != 0) {
          *(byte *)((int)pfVar6 + 0x15) = *(byte *)((int)pfVar6 + 0x15) & 0xfd;
          uStack28 = (int)*(short *)(iVar5 + 0x18) ^ 0x80000000;
          local_20 = 0x43300000;
          *pfVar6 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5360);
        }
        if (*(short *)(iVar5 + 0x1c) == -1) {
          fVar1 = *pfVar6 - FLOAT_803db414;
          *pfVar6 = fVar1;
          if (fVar1 <= FLOAT_803e536c) {
            iVar5 = FUN_8002b9ec();
            dVar7 = (double)FUN_800216d0(param_1 + 0x18,iVar5 + 0x18);
            if ((double)FLOAT_803e5368 < dVar7) {
              *(undefined *)(pfVar6 + 5) = 2;
              *(byte *)((int)pfVar6 + 0x15) = *(byte *)((int)pfVar6 + 0x15) | 2;
            }
            *pfVar6 = FLOAT_803e536c;
          }
        }
        else {
          iVar5 = FUN_8001ffb4();
          if (iVar5 != 0) {
            iVar5 = FUN_8002b9ec();
            dVar7 = (double)FUN_800216d0(param_1 + 0x18,iVar5 + 0x18);
            if ((double)FLOAT_803e5368 < dVar7) {
              *(undefined *)(pfVar6 + 5) = 2;
              *(byte *)((int)pfVar6 + 0x15) = *(byte *)((int)pfVar6 + 0x15) | 2;
            }
          }
        }
        goto LAB_801d2f90;
      }
      FUN_8000da58(param_1,0x3fd);
    }
    else if (uVar4 == 4) {
      FUN_801d2b70(param_1,&DAT_80326d20 + iVar2,pfVar6);
      goto LAB_801d2f90;
    }
    iVar5 = *(int *)(param_1 + 0x4c);
    if ((*(byte *)((int)pfVar6 + 0x15) & 2) != 0) {
      *(byte *)((int)pfVar6 + 0x15) = *(byte *)((int)pfVar6 + 0x15) & 0xfd;
      iVar3 = FUN_800221a0(0xffffffce,0x32);
      uStack28 = *(short *)(iVar5 + 0x1a) + iVar3 ^ 0x80000000;
      local_20 = 0x43300000;
      *pfVar6 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5360);
    }
    if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7f1,0,2,0xffffffff,0);
    }
  }
LAB_801d2f90:
  if (((((&DAT_80326d28)[iVar2] & 1) != 0) &&
      (iVar5 = FUN_80036770(param_1,auStack72,auStack64,&local_44,&local_30,auStack44,local_28),
      iVar5 != 0)) && (local_44 != 0)) {
    if (iVar5 == 0x10) {
      FUN_8002b050(param_1,300);
    }
    else if ((iVar5 - 0xeU < 2) || (iVar5 == 0x11)) {
      FUN_8000bb18(param_1,0x9d);
      local_30 = local_30 + FLOAT_803dcdd8;
      local_28[0] = local_28[0] + FLOAT_803dcddc;
      FUN_8009a1dc((double)FLOAT_803e5380,param_1,auStack60,1,0);
      FUN_8002ac30(param_1,0xf,200,0,0,1);
      *(undefined *)(pfVar6 + 5) = 4;
      *(byte *)((int)pfVar6 + 0x15) = *(byte *)((int)pfVar6 + 0x15) | 2;
      iVar5 = *(int *)(param_1 + 0x50);
      FUN_80035b50(param_1,*(byte *)(iVar5 + 0x62) + 0x50,
                   (int)(short)(*(short *)(iVar5 + 0x68) + -0x50),
                   (int)(short)(*(short *)(iVar5 + 0x6a) + 0x50));
      FUN_80035e8c(param_1);
    }
  }
  if (((&DAT_80326d28)[iVar2] & 8) == 0) {
    FUN_80035f00(param_1);
  }
  else {
    FUN_80035f20(param_1);
  }
  if (((&DAT_80326d28)[iVar2] & 0x10) == 0) {
    FUN_80035dac(param_1);
  }
  else {
    FUN_80035df4(param_1,5,1,0);
  }
  if (((&DAT_80326d28)[iVar2] & 2) == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    if (((*(byte *)(param_1 + 0xaf) & 4) != 0) && (iVar5 = FUN_8001ffb4(0x189), iVar5 == 0)) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      FUN_800200e8(0x189,1);
    }
  }
  if (((&DAT_80326d28)[iVar2] & 4) == 0) {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
  }
  else {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  iVar5 = (int)*(short *)(&DAT_80326d20 + iVar2);
  if (*(short *)(param_1 + 0xa0) != iVar5) {
    FUN_80030334((double)FLOAT_803e536c,param_1,iVar5,0);
  }
  iVar2 = FUN_8002fa48((double)*(float *)(&DAT_80326d24 + iVar2),(double)FLOAT_803db414,param_1,0);
  if (iVar2 == 0) {
    *(byte *)((int)pfVar6 + 0x15) = *(byte *)((int)pfVar6 + 0x15) & 0xfe;
  }
  else {
    *(byte *)((int)pfVar6 + 0x15) = *(byte *)((int)pfVar6 + 0x15) | 1;
  }
  return;
}

