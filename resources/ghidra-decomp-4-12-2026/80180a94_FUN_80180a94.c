// Function: FUN_80180a94
// Entry: 80180a94
// Size: 140 bytes

void FUN_80180a94(int *param_1)

{
  int iVar1;
  int iVar2;
  int aiStack_60 [22];
  
  iVar2 = param_1[0x2e];
  iVar1 = FUN_80064248(param_1 + 0x20,param_1 + 3,(float *)0x2,aiStack_60,param_1,8,0xffffffff,0xff,
                       0);
  if (iVar1 != 0) {
    *(undefined *)(iVar2 + 0x1a) = 1;
  }
  param_1[0x20] = param_1[3];
  param_1[0x21] = param_1[4];
  param_1[0x22] = param_1[5];
  return;
}

