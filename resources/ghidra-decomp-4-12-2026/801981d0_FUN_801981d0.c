// Function: FUN_801981d0
// Entry: 801981d0
// Size: 340 bytes

void FUN_801981d0(int param_1,int param_2)

{
  float fVar1;
  double dVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_800372f8(param_1,0x48);
  *(byte *)(iVar3 + 0x24) = *(byte *)(param_2 + 0x21) & 0xf | *(byte *)(iVar3 + 0x24) & 0xf0;
  fVar1 = FLOAT_803e4d38;
  *(float *)(iVar3 + 0x10) = FLOAT_803e4d38;
  *(float *)(iVar3 + 0x14) = fVar1;
  dVar2 = DOUBLE_803e4d40;
  *(float *)(iVar3 + 8) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1c)) - DOUBLE_803e4d40);
  *(float *)(iVar3 + 0xc) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1d)) - dVar2);
  *(undefined *)(iVar3 + 0x1c) = *(undefined *)(param_2 + 0x1e);
  *(undefined *)(iVar3 + 0x1d) = *(undefined *)(param_2 + 0x1f);
  *(undefined4 *)(iVar3 + 0x20) = *(undefined4 *)(param_2 + 0x18);
  *(byte *)(iVar3 + 0x25) =
       ((*(byte *)(param_2 + 0x20) & 1) != 0) << 7 | *(byte *)(iVar3 + 0x25) & 0x7f;
  *(byte *)(iVar3 + 0x25) =
       ((*(byte *)(param_2 + 0x20) & 2) != 0) << 5 | *(byte *)(iVar3 + 0x25) & 0xdf;
  *(byte *)(iVar3 + 0x25) =
       ((*(byte *)(param_2 + 0x20) & 4) != 0) << 6 | *(byte *)(iVar3 + 0x25) & 0xbf;
  *(float *)(iVar3 + 0x18) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x22) * 0x3c ^ 0x80000000) -
              DOUBLE_803e4d30);
  return;
}

