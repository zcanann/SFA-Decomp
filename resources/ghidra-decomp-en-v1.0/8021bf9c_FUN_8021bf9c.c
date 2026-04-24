// Function: FUN_8021bf9c
// Entry: 8021bf9c
// Size: 308 bytes

undefined4 FUN_8021bf9c(int param_1)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  uint uVar4;
  float *pfVar5;
  
  pfVar5 = *(float **)(param_1 + 0xb8);
  bVar1 = *(byte *)(pfVar5 + 0x5e);
  if ((((bVar1 >> 6 & 1) == 0) && (3 < (bVar1 >> 1 & 0xf))) && (FLOAT_803e6a3c == pfVar5[0x44])) {
    *(byte *)(pfVar5 + 0x5e) = bVar1 & 0xe1;
  }
  uVar4 = FUN_8001ffb4(0x676);
  uVar3 = *(byte *)(pfVar5 + 0x5e) & 1;
  if (uVar3 != uVar4) {
    *(byte *)(pfVar5 + 0x5e) = (byte)uVar3 ^ 1 | *(byte *)(pfVar5 + 0x5e) & 0xfe;
    *pfVar5 = -*pfVar5;
    if ((*(byte *)(pfVar5 + 0x5e) >> 1 & 0xf) == 3) {
      *(byte *)(pfVar5 + 0x5e) = *(byte *)(pfVar5 + 0x5e) & 0xe1;
      *pfVar5 = FLOAT_803e6a38;
    }
    if ((*(byte *)(pfVar5 + 0x5e) >> 1 & 0xf) == 4) {
      *(byte *)(pfVar5 + 0x5e) = *(byte *)(pfVar5 + 0x5e) & 0xe1;
      *pfVar5 = FLOAT_803e6a74;
    }
    if (((*(byte *)(pfVar5 + 0x5e) >> 6 & 1) != 0) && (FLOAT_803e6a3c == *pfVar5)) {
      fVar2 = FLOAT_803e6a38;
      if ((*(byte *)(pfVar5 + 0x5e) & 1) != 0) {
        fVar2 = FLOAT_803e6a74;
      }
      *pfVar5 = fVar2;
    }
    FUN_8000bb18(param_1,0x309);
  }
  return 0;
}

