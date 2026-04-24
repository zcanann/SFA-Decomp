// Function: FUN_802b978c
// Entry: 802b978c
// Size: 356 bytes

undefined4 FUN_802b978c(int param_1,uint *param_2)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x54);
  *param_2 = *param_2 | 0x200000;
  fVar1 = FLOAT_803e8234;
  param_2[0xa5] = (uint)FLOAT_803e8234;
  param_2[0xa1] = (uint)fVar1;
  param_2[0xa0] = (uint)fVar1;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(byte *)(iVar3 + 0xa8e) = *(byte *)(iVar3 + 0xa8e) & 0xf7;
    *(ushort *)(iVar4 + 0x60) = *(ushort *)(iVar4 + 0x60) | 0x200;
    FUN_80030334(param_1,0x204,0);
    param_2[0xa8] = (uint)FLOAT_803e8238;
    FUN_8000bb18(param_1,0x3b3);
  }
  if (((*(ushort *)(iVar4 + 0x60) & 0x200) != 0) && ((*(byte *)(iVar4 + 0xad) & 2) != 0)) {
    *(byte *)(iVar3 + 0xa8e) = *(byte *)(iVar3 + 0xa8e) | 8;
  }
  if ((*(byte *)(iVar3 + 0xa8e) & 8) == 0) {
    *(undefined *)(iVar4 + 0x6e) = 0xb;
    *(undefined *)(iVar4 + 0x6f) = 1;
    *(ushort *)(iVar4 + 0x60) = *(ushort *)(iVar4 + 0x60) | 0x200;
  }
  else {
    *(undefined *)(iVar4 + 0x6e) = 0;
    *(undefined *)(iVar4 + 0x6f) = 0;
    *(ushort *)(iVar4 + 0x60) = *(ushort *)(iVar4 + 0x60) & 0xfdff;
  }
  if (*(float *)(param_1 + 0x98) <= FLOAT_803e823c) {
    uVar2 = 0;
  }
  else {
    uVar2 = 8;
  }
  return uVar2;
}

