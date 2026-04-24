// Function: FUN_8015be08
// Entry: 8015be08
// Size: 236 bytes

undefined4 FUN_8015be08(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2d38;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2d14,param_1,10,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(undefined *)(param_2 + 0x34d) = 1;
  if ((*(uint *)(param_2 + 0x314) & 1) != 0) {
    iVar1 = *(int *)(iVar2 + 0x40c);
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffffe;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 2;
    FUN_8000bb18(param_1,0xcf);
  }
  (**(code **)(*DAT_803dca8c + 0x30))((double)FLOAT_803db414,param_1,param_2,4);
  return 0;
}

