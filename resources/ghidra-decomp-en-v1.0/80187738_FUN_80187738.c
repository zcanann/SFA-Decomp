// Function: FUN_80187738
// Entry: 80187738
// Size: 776 bytes

void FUN_80187738(int param_1)

{
  float fVar1;
  bool bVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  byte *pbVar6;
  
  pbVar6 = *(byte **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar3 = FUN_8002b9ac();
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if ((*(short *)(iVar5 + 0x20) == -1) ||
     (((iVar5 = FUN_8001ffb4(), iVar5 != 0 && (iVar3 != 0)) &&
      (iVar5 = FUN_8001ffb4(0x245), iVar5 != 0)))) {
    bVar2 = true;
  }
  else {
    bVar2 = false;
  }
  if ((*pbVar6 & 3) == 0) {
    if (pbVar6[1] == 0) {
      FUN_80035df4(param_1,9,1,0);
    }
    FUN_80035f20(param_1);
    if (*(short *)(param_1 + 0x46) == 0x102) {
      iVar5 = FUN_8012ebc8();
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
  fVar1 = FLOAT_803e3b00;
  if ((FLOAT_803e3b00 < *(float *)(pbVar6 + 4)) &&
     (*(float *)(pbVar6 + 4) = *(float *)(pbVar6 + 4) - FLOAT_803db414,
     *(float *)(pbVar6 + 4) <= fVar1)) {
    *(undefined *)(param_1 + 0x36) = 0;
    *(float *)(pbVar6 + 4) = fVar1;
    *pbVar6 = *pbVar6 & 0xfe;
    *pbVar6 = *pbVar6 | 2;
    FUN_8002ce88(param_1);
    FUN_80035f00(param_1);
  }
  if ((*pbVar6 & 1) != 0) {
    if (FLOAT_803e3b04 <= *(float *)(pbVar6 + 4)) {
      *(float *)(pbVar6 + 0x10) =
           FLOAT_803e3af8 - (*(float *)(pbVar6 + 4) - FLOAT_803e3b04) / FLOAT_803e3b04;
    }
    else {
      *(float *)(pbVar6 + 0x10) = FLOAT_803e3af8;
    }
    fVar1 = *(float *)(pbVar6 + 4);
    if ((fVar1 < FLOAT_803e3b08) && (FLOAT_803e3b04 < fVar1)) {
      FUN_80030304((double)(FLOAT_803e3af8 - (fVar1 - FLOAT_803e3b04) / FLOAT_803e3b0c),param_1);
    }
    fVar1 = *(float *)(pbVar6 + 4);
    if (fVar1 < FLOAT_803e3b10) {
      if (FLOAT_803e3b04 <= fVar1) {
        *(char *)(param_1 + 0x36) =
             (char)(int)(FLOAT_803e3b14 * ((fVar1 - FLOAT_803e3b04) / FLOAT_803e3b18));
      }
      else {
        *(undefined *)(param_1 + 0x36) = 0;
      }
    }
    *(float *)(pbVar6 + 0xc) = *(float *)(pbVar6 + 0xc) - FLOAT_803db414;
    if (FLOAT_803e3b00 < *(float *)(pbVar6 + 0xc)) {
      uVar4 = 0;
    }
    else {
      uVar4 = 3;
      *(float *)(pbVar6 + 0xc) = *(float *)(pbVar6 + 0xc) + FLOAT_803e3af8;
    }
    FUN_80098b18((double)(FLOAT_803e3b1c * *(float *)(pbVar6 + 0x10) * *(float *)(param_1 + 8)),
                 param_1,3,0,uVar4,0);
    FUN_8000da58(param_1,0x9e);
  }
  return;
}

