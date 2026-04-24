// Function: FUN_8015c7c8
// Entry: 8015c7c8
// Size: 404 bytes

undefined4 FUN_8015c7c8(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) = *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) | 1;
  *(undefined *)(param_2 + 0x25f) = 1;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2d14,param_1,0xb,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_800200e8((int)*(short *)(iVar2 + 0x3f4),1);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(undefined *)(param_2 + 0x34d) = 1;
    *(float *)(param_2 + 0x2a0) =
         FLOAT_803e2d70 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e2d08) /
         FLOAT_803e2d74;
  }
  if (*(char *)(param_2 + 0x346) != '\0') {
    *(undefined2 *)(iVar2 + 0x402) = 1;
  }
  if ((*(uint *)(param_2 + 0x314) & 0x200) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0x20;
  }
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  if (*(float *)(param_1 + 0x98) < FLOAT_803e2d78) {
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 8;
  }
  (**(code **)(*DAT_803dca8c + 0x30))((double)FLOAT_803db414,param_1,param_2,4);
  return 0;
}

