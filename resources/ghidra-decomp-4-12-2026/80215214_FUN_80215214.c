// Function: FUN_80215214
// Entry: 80215214
// Size: 416 bytes

undefined4 FUN_80215214(int param_1)

{
  float fVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  
  uVar5 = 0;
  uVar2 = *(ushort *)(DAT_803de9d4 + 0xfa);
  uVar4 = uVar2 >> 1 & 3;
  if ((uVar2 & 1) == 0) {
    fVar1 = *(float *)(param_1 + 0x294);
  }
  else {
    fVar1 = -*(float *)(param_1 + 0x294);
  }
  *(float *)(DAT_803de9d4 + 8) = fVar1 * FLOAT_803dc074 + *(float *)(DAT_803de9d4 + 8);
  iVar3 = (uint)*(byte *)(DAT_803de9d4 + 0xfc) * 4;
  if (((*(float *)(&DAT_8032b198 + iVar3) < *(float *)(DAT_803de9d4 + 8)) &&
      (FLOAT_803e7450 < fVar1)) ||
     ((*(float *)(DAT_803de9d4 + 8) < *(float *)(&DAT_8032b18c + iVar3) && (fVar1 < FLOAT_803e7450))
     )) {
    if ((uVar2 & 1) == 0) {
      uVar4 = uVar4 + 1;
      if (3 < uVar4) {
        uVar4 = 0;
      }
    }
    else {
      uVar4 = uVar4 - 1;
      if ((int)uVar4 < 0) {
        uVar4 = 3;
      }
    }
    *(ushort *)(DAT_803de9d4 + 0xfa) = *(ushort *)(DAT_803de9d4 + 0xfa) & 0xfff9;
    *(ushort *)(DAT_803de9d4 + 0xfa) = *(ushort *)(DAT_803de9d4 + 0xfa) | (ushort)(uVar4 << 1);
    iVar3 = (uint)*(byte *)(DAT_803de9d4 + 0xfc) * 4;
    if (*(float *)(DAT_803de9d4 + 8) <= *(float *)(&DAT_8032b198 + iVar3)) {
      if (*(float *)(DAT_803de9d4 + 8) < *(float *)(&DAT_8032b18c + iVar3)) {
        *(float *)(DAT_803de9d4 + 8) = *(float *)(&DAT_8032b18c + iVar3);
      }
    }
    else {
      *(float *)(DAT_803de9d4 + 8) = *(float *)(&DAT_8032b198 + iVar3);
    }
    uVar5 = 1;
  }
  iVar3 = uVar4 * 4;
  fVar1 = *(float *)(*(int *)(DAT_803de9d4 + 0xd0) + iVar3);
  *(float *)(DAT_803de9d4 + 0xe8) =
       *(float *)(DAT_803de9d4 + 8) * (*(float *)(*(int *)(DAT_803de9d4 + 0xdc) + iVar3) - fVar1) +
       fVar1;
  fVar1 = *(float *)(*(int *)(DAT_803de9d4 + 0xd4) + iVar3);
  *(float *)(DAT_803de9d4 + 0xec) =
       *(float *)(DAT_803de9d4 + 8) * (*(float *)(*(int *)(DAT_803de9d4 + 0xe0) + iVar3) - fVar1) +
       fVar1;
  fVar1 = *(float *)(*(int *)(DAT_803de9d4 + 0xd8) + iVar3);
  *(float *)(DAT_803de9d4 + 0xf0) =
       *(float *)(DAT_803de9d4 + 8) * (*(float *)(*(int *)(DAT_803de9d4 + 0xe4) + iVar3) - fVar1) +
       fVar1;
  return uVar5;
}

