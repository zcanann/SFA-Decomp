// Function: FUN_8015f3d8
// Entry: 8015f3d8
// Size: 292 bytes

void FUN_8015f3d8(int param_1,int param_2,int param_3)

{
  uint uVar1;
  float *pfVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = 6;
  if (param_3 != 0) {
    uVar1 = 7;
  }
  if ((*(byte *)(param_2 + 0x2b) & 0x20) == 0) {
    uVar1 = uVar1 | 8;
  }
  (**(code **)(*DAT_803dcab8 + 0x58))((double)FLOAT_803e2e14,param_1,param_2,iVar3,7,6,0x102,uVar1);
  *(undefined4 *)(param_1 + 0xbc) = 0;
  pfVar2 = *(float **)(iVar3 + 0x40c);
  uVar1 = FUN_800221a0(10,300);
  *pfVar2 = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e2e08);
  FUN_80030334((double)FLOAT_803e2dc8,param_1,8,0);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar3,0);
  *(undefined2 *)(iVar3 + 0x270) = 0;
  *(undefined *)(iVar3 + 0x25f) = 0;
  FUN_80035f00(param_1);
  return;
}

