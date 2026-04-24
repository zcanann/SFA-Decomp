// Function: FUN_801616ac
// Entry: 801616ac
// Size: 192 bytes

undefined4 FUN_801616ac(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2eb8,param_1,8,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2ee8;
  if ((*(uint *)(param_2 + 0x314) & 0x200) != 0) {
    FUN_8000bb18(param_1,0x233);
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffdff;
    (**(code **)(*DAT_803dcab8 + 0x4c))(param_1,(int)*(short *)(iVar1 + 0x3f0),0xffffffff,1);
  }
  return 0;
}

