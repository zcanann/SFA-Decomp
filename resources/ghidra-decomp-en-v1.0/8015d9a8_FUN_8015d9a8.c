// Function: FUN_8015d9a8
// Entry: 8015d9a8
// Size: 284 bytes

void FUN_8015d9a8(int param_1,int param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = 6;
  if (param_3 != 0) {
    uVar1 = 7;
  }
  if ((*(byte *)(param_2 + 0x2b) & 0x20) == 0) {
    uVar1 = uVar1 | 8;
  }
  (**(code **)(*DAT_803dcab8 + 0x58))
            ((double)FLOAT_803e2db8,param_1,param_2,iVar2,0xe,8,0x102,uVar1);
  *(undefined4 *)(param_1 + 0xbc) = 0;
  if (FLOAT_803e2d24 *
      (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar2 + 0x3fe)) - DOUBLE_803e2d08) <
      FLOAT_803e2d54) {
    *(undefined2 *)(iVar2 + 0x3fe) = 0x6e;
  }
  FUN_80030334((double)FLOAT_803e2d14,param_1,8,0);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar2,0);
  *(undefined2 *)(iVar2 + 0x270) = 0;
  *(undefined *)(iVar2 + 0x25f) = 0;
  return;
}

