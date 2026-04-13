// Function: FUN_80214814
// Entry: 80214814
// Size: 2220 bytes

/* WARNING: Removing unreachable block (ram,0x8021509c) */
/* WARNING: Removing unreachable block (ram,0x80214824) */

void FUN_80214814(uint param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  dVar5 = (double)FLOAT_803e74b0;
  dVar6 = (double)(float)(dVar5 - (double)(*(float *)(DAT_803de9d8 + 0x2c0) / FLOAT_803e74bc));
  dVar4 = (double)FLOAT_803e7450;
  if ((dVar4 <= dVar6) && (dVar4 = dVar6, dVar5 < dVar6)) {
    dVar4 = dVar5;
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x40) != 0) {
    FUN_8000bb38(param_1,0x86);
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x80) != 0) {
    FUN_8000bb38(param_1,0x87);
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x100) != 0) {
    FUN_8000bb38(param_1,0x88);
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x200) != 0) {
    FUN_8000bb38(param_1,0x89);
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x10000) != 0) {
    FUN_8000bb38(param_1,0x8a);
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x40000) != 0) {
    FUN_8000bb38(param_1,0x8b);
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x80000) != 0) {
    FUN_8000bb38(param_1,0x8c);
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x2000) != 0) {
    FUN_8000bb38(param_1,0x8c);
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x1000) != 0) {
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) & 0xffffe7ff;
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x20000) != 0) {
    FUN_8000bb38(param_1,0x8a);
    FUN_8000faf8();
    FUN_8000e69c((double)(float)((double)FLOAT_803e7460 * dVar4));
  }
  if ((*(ushort *)(DAT_803de9d4 + 0xfa) & 0x10) != 0) {
    iVar2 = 0;
    iVar3 = 0;
    do {
      uVar1 = FUN_80022264(0,5);
      if ((uVar1 == 0) && (*(int *)(DAT_803de9d4 + iVar3 + 0x17c) == 0)) {
        uVar1 = FUN_80022264(8,0xc);
        FUN_802126d8(param_1,(short)uVar1,iVar2);
      }
      iVar3 = iVar3 + 4;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 5);
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x4000) != 0) {
    FUN_8000bb38(param_1,0x8e);
    *(byte *)(DAT_803de9d4 + 0x108) = *(byte *)(DAT_803de9d4 + 0x108) ^ 1;
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x8000) != 0) {
    FUN_8000bb38(param_1,0x8f);
    *(byte *)(DAT_803de9d4 + 0x108) = *(byte *)(DAT_803de9d4 + 0x108) ^ 1;
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 3) != 0) {
    FUN_8000bb38(param_1,0x90);
    FUN_80014acc((double)FLOAT_803e7464);
    if ((double)FLOAT_803e744c < dVar4) {
      FUN_8000faf8();
      FUN_8000e69c(dVar4);
      FUN_800201ac(0x554,1);
    }
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0xc) != 0) {
    FUN_80014acc((double)FLOAT_803e74c4);
    FUN_8000bb38(param_1,0x91);
    if ((double)FLOAT_803e744c < dVar4) {
      FUN_8000faf8();
      FUN_8000e69c((double)(float)((double)FLOAT_803e7460 * dVar4));
      FUN_800201ac(0x554,1);
    }
  }
  if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x30) != 0) {
    FUN_80014acc((double)FLOAT_803e74c8);
    FUN_8000bb38(param_1,0x92);
    if ((double)FLOAT_803e744c < dVar4) {
      FUN_8000faf8();
      FUN_8000e69c((double)(float)((double)FLOAT_803e74cc * dVar4));
      FUN_800201ac(0x554,1);
    }
  }
  uVar1 = *(uint *)(DAT_803de9d4 + 0x104);
  if ((uVar1 & 0x100000) == 0) {
    *(uint *)(DAT_803de9d4 + 0x104) = uVar1 & 0x1800;
  }
  else {
    if ((uVar1 & 1) != 0) {
      *(float *)(DAT_803de9d4 + 300) = FLOAT_803e74b0;
      iVar2 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x483,DAT_803de9d4 + 0x124,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x483,DAT_803de9d4 + 0x124,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x484,DAT_803de9d4 + 0x124,0x200001,0xffffffff,0);
        iVar2 = iVar2 + 1;
      } while (iVar2 < 10);
    }
    if ((*(uint *)(DAT_803de9d4 + 0x104) & 2) != 0) {
      *(float *)(DAT_803de9d4 + 0x144) = FLOAT_803e74b0;
      iVar2 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x483,DAT_803de9d4 + 0x13c,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x483,DAT_803de9d4 + 0x13c,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x484,DAT_803de9d4 + 0x13c,0x200001,0xffffffff,0);
        iVar2 = iVar2 + 1;
      } while (iVar2 < 10);
    }
    if ((*(uint *)(DAT_803de9d4 + 0x104) & 4) != 0) {
      *(float *)(DAT_803de9d4 + 300) = FLOAT_803e74d0;
      iVar2 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x483,DAT_803de9d4 + 0x124,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x483,DAT_803de9d4 + 0x124,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x484,DAT_803de9d4 + 0x124,0x200001,0xffffffff,0);
        iVar2 = iVar2 + 1;
      } while (iVar2 < 0xd);
    }
    if ((*(uint *)(DAT_803de9d4 + 0x104) & 8) != 0) {
      *(float *)(DAT_803de9d4 + 0x144) = FLOAT_803e74d0;
      iVar2 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x483,DAT_803de9d4 + 0x13c,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x483,DAT_803de9d4 + 0x13c,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x484,DAT_803de9d4 + 0x13c,0x200001,0xffffffff,0);
        iVar2 = iVar2 + 1;
      } while (iVar2 < 0xd);
    }
    if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x10) != 0) {
      *(float *)(DAT_803de9d4 + 300) = FLOAT_803e7460;
      iVar2 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x483,DAT_803de9d4 + 0x124,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x483,DAT_803de9d4 + 0x124,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x484,DAT_803de9d4 + 0x124,0x200001,0xffffffff,0);
        iVar2 = iVar2 + 1;
      } while (iVar2 < 0x10);
    }
    if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x20) != 0) {
      *(float *)(DAT_803de9d4 + 0x144) = FLOAT_803e7460;
      iVar2 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x483,DAT_803de9d4 + 0x13c,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x483,DAT_803de9d4 + 0x13c,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x484,DAT_803de9d4 + 0x13c,0x200001,0xffffffff,0);
        iVar2 = iVar2 + 1;
      } while (iVar2 < 0x10);
    }
    if ((*(uint *)(DAT_803de9d4 + 0x104) & 0x800) != 0) {
      (**(code **)(*DAT_803dd708 + 8))
                (param_1,0x487,DAT_803de9d4 + 0x10c,0x200001,0xffffffff,DAT_803de9d4 + 0x16c);
    }
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) & 0x1800;
    iVar2 = FUN_8002bac4();
    if (*(int *)(*(int *)(param_1 + 0x54) + 0x50) == iVar2) {
      uVar1 = FUN_8002bac4();
      FUN_8000bb38(uVar1,0x2b9);
    }
  }
  return;
}

