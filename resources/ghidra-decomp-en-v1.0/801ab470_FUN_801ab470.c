// Function: FUN_801ab470
// Entry: 801ab470
// Size: 612 bytes

void FUN_801ab470(int param_1)

{
  int iVar1;
  char cVar2;
  float *pfVar3;
  double dVar4;
  undefined auStack40 [12];
  float local_1c;
  float local_18;
  float local_14;
  
  iVar1 = FUN_8001ffb4((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1a));
  if (iVar1 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    iVar1 = FUN_8001ffb4(0x40);
    if (iVar1 == 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    }
    pfVar3 = *(float **)(param_1 + 0xb8);
    iVar1 = FUN_80038024(param_1);
    if ((iVar1 != 0) && (cVar2 = FUN_801334e0(), cVar2 == '\0')) {
      *pfVar3 = FLOAT_803e46c0;
    }
    if (FLOAT_803e46b0 < *pfVar3) {
      if ((*(byte *)(param_1 + 0xaf) & 4) == 0) {
        *pfVar3 = FLOAT_803e46b0;
      }
      else {
        *pfVar3 = *pfVar3 - FLOAT_803db414;
        FUN_8012ef30((int)*(short *)(*(int *)(param_1 + 0x50) + 0x7c));
      }
    }
    iVar1 = FUN_8002b9ec();
    dVar4 = (double)FUN_800216d0(param_1 + 0x18,iVar1 + 0x18);
    if ((dVar4 < (double)FLOAT_803e46c4) && (iVar1 = FUN_80295cd4(iVar1), iVar1 != 0)) {
      FUN_8000bb18(param_1,0x109);
      FUN_800200e8((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1a),1);
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    local_1c = FLOAT_803e46a8;
    local_18 = FLOAT_803e46ac;
    local_14 = FLOAT_803e46b0;
    FUN_80097734((double)FLOAT_803e46b4,(double)FLOAT_803e46b8,(double)FLOAT_803e46b8,
                 (double)FLOAT_803e46bc,param_1,5,5,2,0x19,auStack40,0);
    local_1c = FLOAT_803e46ac;
    FUN_80097734((double)FLOAT_803e46b4,(double)FLOAT_803e46b8,(double)FLOAT_803e46b8,
                 (double)FLOAT_803e46bc,param_1,5,5,2,0x19,auStack40,0);
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    local_1c = FLOAT_803e46a8;
    local_18 = FLOAT_803e46ac;
    local_14 = FLOAT_803e46b0;
    FUN_80097734((double)FLOAT_803e46b4,(double)FLOAT_803e46b8,(double)FLOAT_803e46b8,
                 (double)FLOAT_803e46bc,param_1,5,2,2,0x19,auStack40,0);
    local_1c = FLOAT_803e46ac;
    FUN_80097734((double)FLOAT_803e46b4,(double)FLOAT_803e46b8,(double)FLOAT_803e46b8,
                 (double)FLOAT_803e46bc,param_1,5,2,2,0x19,auStack40,0);
  }
  return;
}

