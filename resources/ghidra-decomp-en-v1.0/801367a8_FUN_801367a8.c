// Function: FUN_801367a8
// Entry: 801367a8
// Size: 252 bytes

void FUN_801367a8(undefined2 *param_1,int param_2)

{
  short sVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar2 + 0x30) = 0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  sVar1 = param_1[0x23];
  if ((sVar1 < 0x77d) || (0x780 < sVar1)) {
    *(float *)(iVar2 + 0x34) = FLOAT_803e22f8;
    *(undefined *)(iVar2 + 0x31) = 0xfe;
    if (param_1[0x23] == 0x78a) {
      FUN_80030334(param_1,1,0);
    }
    else if (param_1[0x23] == 0x781) {
      FUN_80030334((double)FLOAT_803e2318,param_1,0,0);
      FUN_8002853c(**(undefined4 **)(param_1 + 0x3e),FUN_80118294);
    }
  }
  else {
    *(char *)(iVar2 + 0x31) = (char)sVar1 + -0x7d;
    *(undefined4 *)(iVar2 + 0x34) = *(undefined4 *)(&DAT_8030de70 + (short)param_1[0x23] * 0x20);
    FUN_80030334((double)FLOAT_803e22f8,param_1,0,0);
  }
  return;
}

