// Function: FUN_80167b60
// Entry: 80167b60
// Size: 432 bytes

undefined4 FUN_80167b60(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_2 + 0x34d) = 3;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e3084;
  fVar1 = FLOAT_803e3060;
  *(float *)(param_2 + 0x280) = FLOAT_803e3060;
  *(float *)(param_2 + 0x284) = fVar1;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334(param_1,5,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  if ((*(uint *)(param_2 + 0x314) & 0x1000) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xffffefff;
    FUN_80169360(param_1,2);
  }
  iVar3 = *(int *)(iVar2 + 0x40c);
  if ((*(byte *)(iVar3 + 0x4b) & 1) == 0) {
    FUN_8000bb18(param_1,0x274);
    FUN_8000bb18(param_1,0x277);
    FUN_8000bb18(param_1,0x232);
    *(byte *)(iVar3 + 0x4b) = *(byte *)(iVar3 + 0x4b) | 1;
    if (*(short *)(iVar2 + 0x3f0) == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = (**(code **)(*DAT_803dcab8 + 0x4c))(param_1,6,0xffffffff,0);
    }
    if (iVar2 != 0) {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x2c))
                ((double)FLOAT_803e3060,(double)FLOAT_803e3078,(double)FLOAT_803e3060);
    }
  }
  if (((*(byte *)(iVar3 + 0x4b) & 2) == 0) && (FLOAT_803e3088 < *(float *)(param_1 + 0x98))) {
    FUN_8000bb18(param_1,0x233);
    *(byte *)(iVar3 + 0x4b) = *(byte *)(iVar3 + 0x4b) | 2;
  }
  *(char *)(param_1 + 0x36) =
       (char)(int)(FLOAT_803e308c * (FLOAT_803e3078 - *(float *)(param_1 + 0x98)));
  return 0;
}

