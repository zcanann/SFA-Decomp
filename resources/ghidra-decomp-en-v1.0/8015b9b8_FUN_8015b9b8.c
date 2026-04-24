// Function: FUN_8015b9b8
// Entry: 8015b9b8
// Size: 328 bytes

undefined4 FUN_8015b9b8(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_2 + 0x34d) = 3;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2d28;
  fVar1 = FLOAT_803e2d14;
  *(float *)(param_2 + 0x280) = FLOAT_803e2d14;
  *(float *)(param_2 + 0x284) = fVar1;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334(param_1,1,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  if ((*(byte *)(param_2 + 0x356) & 1) == 0) {
    iVar2 = FUN_8002b9ec();
    if (*(short *)(iVar2 + 0x46) == 0) {
      FUN_8000bb18(param_1,0x239);
    }
    else {
      FUN_8000bb18(param_1,0x1f2);
    }
    FUN_8000bb18(param_1,0x232);
    FUN_8000bb18(param_1,0x26f);
    *(byte *)(param_2 + 0x356) = *(byte *)(param_2 + 0x356) | 1;
  }
  if (((*(byte *)(param_2 + 0x356) & 2) == 0) && (FLOAT_803e2d2c < *(float *)(param_1 + 0x98))) {
    FUN_8000bb18(param_1,0x233);
    *(byte *)(param_2 + 0x356) = *(byte *)(param_2 + 0x356) | 2;
    (**(code **)(*DAT_803dcab8 + 0x4c))(param_1,(int)*(short *)(iVar3 + 0x3f0),0xffffffff,0);
  }
  return 0;
}

