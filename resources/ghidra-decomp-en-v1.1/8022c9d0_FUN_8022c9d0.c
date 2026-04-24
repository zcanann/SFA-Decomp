// Function: FUN_8022c9d0
// Entry: 8022c9d0
// Size: 884 bytes

/* WARNING: Removing unreachable block (ram,0x8022cd20) */
/* WARNING: Removing unreachable block (ram,0x8022c9e0) */

void FUN_8022c9d0(uint param_1,int param_2)

{
  float fVar1;
  float fVar2;
  undefined2 uVar3;
  int iVar4;
  uint uVar5;
  double dVar6;
  
  iVar4 = FUN_800396d0(*(int *)(param_2 + 4),0x14);
  if (((*(byte *)(param_2 + 0x478) < 4) && (uVar5 = FUN_80020078(0x9d6), uVar5 == 0)) &&
     (uVar5 = FUN_80020078(0x9d8), uVar5 == 0)) {
    dVar6 = FUN_80294d40((double)(*(float *)(param_2 + 0x50) / *(float *)(param_2 + 0x5c)));
    dVar6 = (double)(float)((DOUBLE_803e7be0 + dVar6) * DOUBLE_803e7be8);
    FUN_8000da78(param_1,0x29f);
    FUN_8000b8a8(dVar6,param_1,0x40,0xfe);
  }
  FUN_8022f934(*(int *)(param_2 + 4),(uint)*(ushort *)(param_2 + 0x44e));
  if (FLOAT_803e7b64 < *(float *)(param_2 + 0xb4)) {
    if ((*(ushort *)(param_2 + 0x3f4) & 0xc00) != 0) {
      FUN_8000bb38(param_1,0x381);
    }
    *(float *)(param_2 + 0xb4) = *(float *)(param_2 + 0xb4) - FLOAT_803dc074;
    if (*(float *)(param_2 + 0xb4) <= FLOAT_803e7b64) {
      *(float *)(param_2 + 0xb0) = FLOAT_803e7bf4;
    }
  }
  else {
    if ((*(byte *)(param_2 + 0x477) & 2) == 0) {
      if ((*(ushort *)(param_2 + 0x3f4) & 0x800) != 0) {
        *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) & 0xfb;
        *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) | 2;
        *(float *)(param_2 + 0xb0) = FLOAT_803e7bf0;
        FUN_8000b4f0(param_1,0x2b6,3);
      }
    }
    else {
      *(undefined4 *)(param_2 + 0x6c) = *(undefined4 *)(param_2 + 0x88);
      *(undefined4 *)(param_2 + 0x68) = *(undefined4 *)(param_2 + 0x90);
      if ((*(ushort *)(param_2 + 0x3f6) & 0x800) != 0) {
        *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) & 0xfd;
        *(float *)(param_2 + 0xb0) = FLOAT_803e7bf4;
      }
    }
    if ((*(byte *)(param_2 + 0x477) & 4) == 0) {
      if ((*(ushort *)(param_2 + 0x3f4) & 0x400) != 0) {
        *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) & 0xfd;
        *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) | 4;
        *(float *)(param_2 + 0xb0) = FLOAT_803e7bf8;
        FUN_8000b4f0(param_1,0x2b7,3);
      }
    }
    else {
      *(undefined4 *)(param_2 + 0x6c) = *(undefined4 *)(param_2 + 0x8c);
      *(undefined4 *)(param_2 + 0x68) = *(undefined4 *)(param_2 + 0x94);
      if ((*(ushort *)(param_2 + 0x3f6) & 0x400) != 0) {
        *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) & 0xfb;
        *(float *)(param_2 + 0xb0) = FLOAT_803e7bf4;
      }
    }
  }
  if ((*(byte *)(param_2 + 0x477) & 6) == 0) {
    *(float *)(param_2 + 0x6c) = FLOAT_803e7b68;
    *(undefined4 *)(param_2 + 0x68) = *(undefined4 *)(param_2 + 0x98);
    if (FLOAT_803e7b64 < *(float *)(param_2 + 0xbc)) {
      *(float *)(param_2 + 0xbc) = *(float *)(param_2 + 0xbc) - FLOAT_803dc074;
    }
    else {
      *(float *)(param_2 + 0x9c) = FLOAT_803e7bfc * FLOAT_803dc074 + *(float *)(param_2 + 0x9c);
    }
  }
  else {
    *(float *)(param_2 + 0x9c) = *(float *)(param_2 + 0x9c) - FLOAT_803dc074;
    *(float *)(param_2 + 0xbc) = FLOAT_803e7bd0;
  }
  fVar1 = *(float *)(param_2 + 0x9c);
  fVar2 = FLOAT_803e7b64;
  if ((FLOAT_803e7b64 <= fVar1) && (fVar2 = fVar1, *(float *)(param_2 + 0xa0) < fVar1)) {
    fVar2 = *(float *)(param_2 + 0xa0);
  }
  *(float *)(param_2 + 0x9c) = fVar2;
  fVar1 = FLOAT_803e7b64;
  if (*(float *)(param_2 + 0x9c) <= FLOAT_803e7b64) {
    *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) & 0xf9;
    *(undefined4 *)(param_2 + 0xb4) = *(undefined4 *)(param_2 + 0xb8);
    *(undefined4 *)(param_2 + 0x9c) = *(undefined4 *)(param_2 + 0xa0);
    *(float *)(param_2 + 0xb0) = FLOAT_803e7c00;
    *(float *)(param_2 + 0xbc) = fVar1;
  }
  if (iVar4 != 0) {
    *(float *)(param_2 + 0xac) =
         FLOAT_803e7b90 * (*(float *)(param_2 + 0xb0) - *(float *)(param_2 + 0xac)) +
         *(float *)(param_2 + 0xac);
    uVar3 = (undefined2)(int)*(float *)(param_2 + 0xac);
    *(undefined2 *)(iVar4 + 10) = uVar3;
    *(undefined2 *)(iVar4 + 8) = uVar3;
    *(undefined2 *)(iVar4 + 6) = uVar3;
  }
  return;
}

