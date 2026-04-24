// Function: FUN_8018b528
// Entry: 8018b528
// Size: 132 bytes

void FUN_8018b528(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  int iVar2;
  char *pcVar3;
  undefined8 uVar4;
  
  pcVar3 = *(char **)(param_9 + 0xb8);
  iVar2 = *(int *)(param_9 + 0x4c);
  uVar4 = FUN_80014a54();
  iVar1 = FUN_8002bac4();
  if ((iVar1 != 0) && (iVar1 = FUN_80296e2c(iVar1), iVar1 != 0)) {
    uVar4 = FUN_8016de98(iVar1,5,0);
  }
  if ((*pcVar3 == '\x01') && (*(char *)(iVar2 + 0x22) == '\0')) {
    FUN_8004832c((uint)*(byte *)(iVar2 + 0x1f));
    FUN_80043938(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return;
}

