// Function: FUN_802119b4
// Entry: 802119b4
// Size: 188 bytes

void FUN_802119b4(int param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = FUN_800803dc((float *)(*(int *)(param_1 + 0xb8) + 0x14));
  if (uVar2 == 0) {
    iVar3 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    fVar1 = FLOAT_803e7400;
    if (((*(char *)(*(int *)(param_1 + 0x54) + 0xad) != '\0') || (iVar3 != 0)) ||
       (*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0)) {
      iVar3 = *(int *)(param_1 + 0xb8);
      *(float *)(param_1 + 0x28) = FLOAT_803e7400;
      *(float *)(param_1 + 0x24) = fVar1;
      *(float *)(param_1 + 0x2c) = fVar1;
      *(undefined *)(iVar3 + 0x2c) = 0;
      FUN_800803f8((undefined4 *)(iVar3 + 0x1c));
      FUN_80080404((float *)(iVar3 + 0x1c),1);
      FUN_80080404((float *)(iVar3 + 0x14),10);
    }
  }
  return;
}

