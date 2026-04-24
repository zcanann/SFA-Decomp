// Function: FUN_80168018
// Entry: 80168018
// Size: 256 bytes

undefined4 FUN_80168018(int param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  bVar1 = *(char *)(param_2 + 0x27a) == '\0';
  if (bVar1) {
    if (*(char *)(param_2 + 0x346) != '\0') {
      FUN_800200e8((int)*(short *)(iVar2 + 0x3f4),0);
      if (*(char *)(param_2 + 0x27a) != '\0') {
        FUN_80030334((double)FLOAT_803e3060,param_1,4,0);
        *(undefined *)(param_2 + 0x346) = 0;
      }
      *(undefined2 *)(iVar2 + 0x402) = 0;
    }
  }
  else {
    if (!bVar1) {
      FUN_80030334((double)FLOAT_803e3060,param_1,5,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    FUN_80035f00(param_1);
    *(float *)(param_2 + 0x2a0) = FLOAT_803e307c;
    *(float *)(param_2 + 0x280) = FLOAT_803e3060;
  }
  if ((*(uint *)(param_2 + 0x314) & 0x1000) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xffffefff;
    FUN_80169360(param_1,2);
  }
  return 0;
}

