// Function: FUN_8021419c
// Entry: 8021419c
// Size: 2220 bytes

/* WARNING: Removing unreachable block (ram,0x80214a24) */

void FUN_8021419c(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  dVar8 = (double)FLOAT_803e6818;
  dVar9 = (double)(float)(dVar8 - (double)(*(float *)(DAT_803ddd58 + 0x2c0) / FLOAT_803e6824));
  dVar7 = (double)FLOAT_803e67b8;
  if ((dVar7 <= dVar9) && (dVar7 = dVar9, dVar8 < dVar9)) {
    dVar7 = dVar8;
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x40) != 0) {
    FUN_8000bb18(param_1,0x86);
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x80) != 0) {
    FUN_8000bb18(param_1,0x87);
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x100) != 0) {
    FUN_8000bb18(param_1,0x88);
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x200) != 0) {
    FUN_8000bb18(param_1,0x89);
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x10000) != 0) {
    FUN_8000bb18(param_1,0x8a);
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x40000) != 0) {
    FUN_8000bb18(param_1,0x8b);
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x80000) != 0) {
    FUN_8000bb18(param_1,0x8c);
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x2000) != 0) {
    FUN_8000bb18(param_1,0x8c);
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x1000) != 0) {
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) & 0xffffe7ff;
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x20000) != 0) {
    FUN_8000bb18(param_1,0x8a);
    FUN_8000fad8();
    FUN_8000e67c((double)(float)((double)FLOAT_803e67c8 * dVar7));
  }
  if ((*(ushort *)(DAT_803ddd54 + 0xfa) & 0x10) != 0) {
    iVar4 = 0;
    iVar5 = 0;
    do {
      iVar1 = FUN_800221a0(0,5);
      if ((iVar1 == 0) && (*(int *)(DAT_803ddd54 + iVar5 + 0x17c) == 0)) {
        uVar2 = FUN_800221a0(8,0xc);
        FUN_80212060((double)FLOAT_803e6828,param_1,uVar2,iVar4);
      }
      iVar5 = iVar5 + 4;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 5);
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x4000) != 0) {
    FUN_8000bb18(param_1,0x8e);
    *(byte *)(DAT_803ddd54 + 0x108) = *(byte *)(DAT_803ddd54 + 0x108) ^ 1;
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x8000) != 0) {
    FUN_8000bb18(param_1,0x8f);
    *(byte *)(DAT_803ddd54 + 0x108) = *(byte *)(DAT_803ddd54 + 0x108) ^ 1;
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 3) != 0) {
    FUN_8000bb18(param_1,0x90);
    FUN_80014aa0((double)FLOAT_803e67cc);
    if ((double)FLOAT_803e67b4 < dVar7) {
      FUN_8000fad8();
      FUN_8000e67c(dVar7);
      FUN_800200e8(0x554,1);
    }
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0xc) != 0) {
    FUN_80014aa0((double)FLOAT_803e682c);
    FUN_8000bb18(param_1,0x91);
    if ((double)FLOAT_803e67b4 < dVar7) {
      FUN_8000fad8();
      FUN_8000e67c((double)(float)((double)FLOAT_803e67c8 * dVar7));
      FUN_800200e8(0x554,1);
    }
  }
  if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x30) != 0) {
    FUN_80014aa0((double)FLOAT_803e6830);
    FUN_8000bb18(param_1,0x92);
    if ((double)FLOAT_803e67b4 < dVar7) {
      FUN_8000fad8();
      FUN_8000e67c((double)(float)((double)FLOAT_803e6834 * dVar7));
      FUN_800200e8(0x554,1);
    }
  }
  uVar3 = *(uint *)(DAT_803ddd54 + 0x104);
  if ((uVar3 & 0x100000) == 0) {
    *(uint *)(DAT_803ddd54 + 0x104) = uVar3 & 0x1800;
  }
  else {
    if ((uVar3 & 1) != 0) {
      *(float *)(DAT_803ddd54 + 300) = FLOAT_803e6818;
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x483,DAT_803ddd54 + 0x124,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x483,DAT_803ddd54 + 0x124,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x484,DAT_803ddd54 + 0x124,0x200001,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 10);
    }
    if ((*(uint *)(DAT_803ddd54 + 0x104) & 2) != 0) {
      *(float *)(DAT_803ddd54 + 0x144) = FLOAT_803e6818;
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x483,DAT_803ddd54 + 0x13c,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x483,DAT_803ddd54 + 0x13c,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x484,DAT_803ddd54 + 0x13c,0x200001,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 10);
    }
    if ((*(uint *)(DAT_803ddd54 + 0x104) & 4) != 0) {
      *(float *)(DAT_803ddd54 + 300) = FLOAT_803e6838;
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x483,DAT_803ddd54 + 0x124,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x483,DAT_803ddd54 + 0x124,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x484,DAT_803ddd54 + 0x124,0x200001,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0xd);
    }
    if ((*(uint *)(DAT_803ddd54 + 0x104) & 8) != 0) {
      *(float *)(DAT_803ddd54 + 0x144) = FLOAT_803e6838;
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x483,DAT_803ddd54 + 0x13c,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x483,DAT_803ddd54 + 0x13c,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x484,DAT_803ddd54 + 0x13c,0x200001,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0xd);
    }
    if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x10) != 0) {
      *(float *)(DAT_803ddd54 + 300) = FLOAT_803e67c8;
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x483,DAT_803ddd54 + 0x124,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x483,DAT_803ddd54 + 0x124,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x484,DAT_803ddd54 + 0x124,0x200001,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x10);
    }
    if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x20) != 0) {
      *(float *)(DAT_803ddd54 + 0x144) = FLOAT_803e67c8;
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x483,DAT_803ddd54 + 0x13c,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x483,DAT_803ddd54 + 0x13c,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x484,DAT_803ddd54 + 0x13c,0x200001,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x10);
    }
    if ((*(uint *)(DAT_803ddd54 + 0x104) & 0x800) != 0) {
      (**(code **)(*DAT_803dca88 + 8))
                (param_1,0x487,DAT_803ddd54 + 0x10c,0x200001,0xffffffff,DAT_803ddd54 + 0x16c);
    }
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) & 0x1800;
    iVar4 = FUN_8002b9ec();
    if (*(int *)(*(int *)(param_1 + 0x54) + 0x50) == iVar4) {
      uVar2 = FUN_8002b9ec();
      FUN_8000bb18(uVar2,0x2b9);
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

