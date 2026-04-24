// Function: FUN_80202428
// Entry: 80202428
// Size: 252 bytes

undefined4 FUN_80202428(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80035f20();
  }
  FUN_80035df4(param_1,10,1,0xffffffff);
  *(float *)(param_2 + 0x2a0) = FLOAT_803e62f4;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e62a8,param_1,10,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(undefined *)(param_2 + 0x34d) = 1;
  iVar1 = *(int *)(iVar1 + 0x40c);
  *(byte *)(iVar1 + 0x14) = *(byte *)(iVar1 + 0x14) | 2;
  if ((*(uint *)(param_2 + 0x314) & 1) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffffe;
    *(byte *)(iVar1 + 0x14) = *(byte *)(iVar1 + 0x14) | 1;
  }
  if (*(char *)(param_2 + 0x346) != '\0') {
    *(undefined *)(iVar1 + 0x34) = 1;
  }
  return 0;
}

