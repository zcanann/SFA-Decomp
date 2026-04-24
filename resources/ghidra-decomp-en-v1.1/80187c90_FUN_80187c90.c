// Function: FUN_80187c90
// Entry: 80187c90
// Size: 776 bytes

void FUN_80187c90(uint param_1)

{
  float fVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  byte *pbVar6;
  
  pbVar6 = *(byte **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar3 = FUN_8002ba84();
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  uVar4 = (uint)*(short *)(iVar5 + 0x20);
  if ((uVar4 == 0xffffffff) ||
     (((uVar4 = FUN_80020078(uVar4), uVar4 != 0 && (iVar3 != 0)) &&
      (uVar4 = FUN_80020078(0x245), uVar4 != 0)))) {
    bVar2 = true;
  }
  else {
    bVar2 = false;
  }
  if ((*pbVar6 & 3) == 0) {
    if (pbVar6[1] == 0) {
      FUN_80035eec(param_1,9,1,0);
    }
    FUN_80036018(param_1);
    if (*(short *)(param_1 + 0x46) == 0x102) {
      iVar5 = FUN_8012f000();
      if (iVar5 == -1) {
        *(undefined *)(*(int *)(*(int *)(param_1 + 0x50) + 0x40) + 0x11) = 0;
      }
      else {
        *(undefined *)(*(int *)(*(int *)(param_1 + 0x50) + 0x40) + 0x11) = 0x10;
      }
    }
    if (((iVar3 != 0) && (bVar2)) &&
       (*(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7,
       (*(byte *)(param_1 + 0xaf) & 4) != 0)) {
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,param_1,1,4);
    }
  }
  fVar1 = FLOAT_803e4798;
  if (FLOAT_803e4798 < *(float *)(pbVar6 + 4)) {
    *(float *)(pbVar6 + 4) = *(float *)(pbVar6 + 4) - FLOAT_803dc074;
    if (*(float *)(pbVar6 + 4) <= fVar1) {
      *(undefined *)(param_1 + 0x36) = 0;
      *(float *)(pbVar6 + 4) = fVar1;
      *pbVar6 = *pbVar6 & 0xfe;
      *pbVar6 = *pbVar6 | 2;
      FUN_8002cf80(param_1);
      FUN_80035ff8(param_1);
    }
  }
  if ((*pbVar6 & 1) != 0) {
    if (FLOAT_803e479c <= *(float *)(pbVar6 + 4)) {
      *(float *)(pbVar6 + 0x10) =
           FLOAT_803e4790 - (*(float *)(pbVar6 + 4) - FLOAT_803e479c) / FLOAT_803e479c;
    }
    else {
      *(float *)(pbVar6 + 0x10) = FLOAT_803e4790;
    }
    fVar1 = *(float *)(pbVar6 + 4);
    if ((fVar1 < FLOAT_803e47a0) && (FLOAT_803e479c < fVar1)) {
      FUN_800303fc((double)(FLOAT_803e4790 - (fVar1 - FLOAT_803e479c) / FLOAT_803e47a4),param_1);
    }
    fVar1 = *(float *)(pbVar6 + 4);
    if (fVar1 < FLOAT_803e47a8) {
      if (FLOAT_803e479c <= fVar1) {
        *(char *)(param_1 + 0x36) =
             (char)(int)(FLOAT_803e47ac * ((fVar1 - FLOAT_803e479c) / FLOAT_803e47b0));
      }
      else {
        *(undefined *)(param_1 + 0x36) = 0;
      }
    }
    *(float *)(pbVar6 + 0xc) = *(float *)(pbVar6 + 0xc) - FLOAT_803dc074;
    if (FLOAT_803e4798 < *(float *)(pbVar6 + 0xc)) {
      uVar4 = 0;
    }
    else {
      uVar4 = 3;
      *(float *)(pbVar6 + 0xc) = *(float *)(pbVar6 + 0xc) + FLOAT_803e4790;
    }
    FUN_80098da4(param_1,3,0,uVar4,(undefined4 *)0x0);
    FUN_8000da78(param_1,0x9e);
  }
  return;
}

