// Function: FUN_801ff094
// Entry: 801ff094
// Size: 212 bytes

void FUN_801ff094(int *param_1)

{
  float fVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = FUN_80036974((int)param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  iVar3 = param_1[0x2e];
  if ((iVar2 == 0x12) && (*(char *)(iVar3 + 0x118) != '\x04')) {
    FUN_8002bac4();
  }
  if (*(char *)(iVar3 + 0x118) != '\t') {
    iVar2 = FUN_80064248(param_1 + 0x20,param_1 + 3,(float *)0x1,(int *)0x0,param_1,8,0xffffffff,
                         0xff,0);
    fVar1 = FLOAT_803e6eb4;
    if (iVar2 != 0) {
      param_1[9] = (int)-(FLOAT_803e6eb4 * (float)param_1[9] - (float)param_1[9]);
      param_1[0xb] = (int)-(fVar1 * (float)param_1[0xb] - (float)param_1[0xb]);
    }
  }
  param_1[0x20] = param_1[3];
  param_1[0x21] = param_1[4];
  param_1[0x22] = param_1[5];
  return;
}

