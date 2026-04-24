// Function: FUN_8022bb40
// Entry: 8022bb40
// Size: 396 bytes

void FUN_8022bb40(undefined4 param_1,int param_2)

{
  bool bVar1;
  float fVar2;
  
  FUN_8022a9c8();
  fVar2 = FLOAT_803e6ecc;
  if (FLOAT_803e6ecc < *(float *)(param_2 + 0x408)) {
    *(float *)(param_2 + 0x408) = *(float *)(param_2 + 0x408) - FLOAT_803db414;
    if (fVar2 <= *(float *)(param_2 + 0x408)) {
      return;
    }
    *(float *)(param_2 + 0x408) = fVar2;
  }
  bVar1 = false;
  if (((*(ushort *)(param_2 + 0x3f8) & 0x100) != 0) &&
     (*(float *)(param_2 + 0x414) = *(float *)(param_2 + 0x414) - FLOAT_803db414,
     *(float *)(param_2 + 0x414) <= FLOAT_803e6ecc)) {
    bVar1 = true;
  }
  if (((*(ushort *)(param_2 + 0x3f4) & 0x100) != 0) || (bVar1)) {
    *(float *)(param_2 + 0x414) = FLOAT_803e6f04;
    if (*(char *)(param_2 + 0x404) == '\x02') {
      FUN_8022b998(param_1,param_2,0,2,1);
      FUN_8022b998(param_1,param_2,1,2,0);
    }
    else if (*(char *)(param_2 + 0x404) == '\x01') {
      FUN_8022b998(param_1,param_2,0,1,1);
      FUN_8022b998(param_1,param_2,1,1,0);
    }
    else {
      FUN_8022b998(param_1,param_2,*(undefined *)(param_2 + 0x405),0,1);
      *(byte *)(param_2 + 0x405) = *(byte *)(param_2 + 0x405) ^ 1;
    }
    *(float *)(param_2 + 0x408) =
         (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x40c)) - DOUBLE_803e6ee8);
  }
  return;
}

