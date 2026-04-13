// Function: FUN_801cf5c4
// Entry: 801cf5c4
// Size: 156 bytes

void FUN_801cf5c4(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8003b9ec(param_1);
  iVar2 = 0;
  iVar3 = iVar1;
  do {
    FUN_80038524(param_1,iVar2,(float *)(iVar3 + 0x45c),(undefined4 *)(iVar3 + 0x460),
                 (float *)(iVar3 + 0x464),0);
    iVar3 = iVar3 + 0xc;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  FUN_80038524(param_1,4,(float *)(iVar1 + 0xc),(undefined4 *)(iVar1 + 0x10),(float *)(iVar1 + 0x14)
               ,0);
  return;
}

