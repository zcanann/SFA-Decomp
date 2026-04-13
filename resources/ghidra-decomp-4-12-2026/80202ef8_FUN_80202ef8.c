// Function: FUN_80202ef8
// Entry: 80202ef8
// Size: 364 bytes

undefined4 FUN_80202ef8(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  if (*(char *)(param_2 + 0x27a) == '\0') {
    FUN_80035eec(param_1,10,1,-1);
  }
  else {
    *(undefined *)(param_2 + 0x25f) = 1;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(undefined *)(param_2 + 0x34d) = 1;
    *(float *)(param_2 + 0x2a0) =
         FLOAT_803e6fe8 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e6f78) /
         FLOAT_803e6fec;
    FUN_80036018(param_1);
    *(undefined4 *)(iVar1 + 0x18) = 0;
    *(undefined2 *)(iVar1 + 0x1c) = 0xffff;
  }
  if (*(char *)(param_2 + 0x346) != '\0') {
    *(undefined2 *)(iVar2 + 0x402) = 1;
    *(undefined *)(iVar1 + 0x34) = 1;
  }
  if ((*(uint *)(param_2 + 0x314) & 0x200) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x14) = *(byte *)(iVar1 + 0x14) | 4;
  }
  if (*(float *)(param_1 + 0x98) < FLOAT_803e6ff0) {
    *(byte *)(iVar1 + 0x14) = *(byte *)(iVar1 + 0x14) | 2;
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_1,param_2,7,0,&DAT_8032a280);
  return 0;
}

