// Function: FUN_801a917c
// Entry: 801a917c
// Size: 380 bytes

void FUN_801a917c(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int local_28;
  int local_24;
  undefined4 local_20;
  uint uStack28;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if ((*(int *)(param_1 + 0x4c) != 0) && (*(short *)(*(int *)(param_1 + 0x4c) + 0x18) != -1)) {
    uStack28 = (uint)DAT_803db410;
    local_20 = 0x43300000;
    local_24 = (**(code **)(*DAT_803dca54 + 0x14))
                         ((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e45d0));
    FUN_801a8f88(param_1,iVar4);
    if ((local_24 != 0) && (*(short *)(param_1 + 0xb4) == -2)) {
      iVar5 = (int)*(char *)(iVar4 + 0x57);
      iVar4 = 0;
      piVar1 = (int *)FUN_8002e0fc(&local_24,&local_28);
      iVar3 = 0;
      for (local_24 = 0; local_24 < local_28; local_24 = local_24 + 1) {
        iVar2 = *piVar1;
        if (*(short *)(iVar2 + 0xb4) == iVar5) {
          iVar4 = iVar2;
        }
        if (((*(short *)(iVar2 + 0xb4) == -2) && (*(short *)(iVar2 + 0x44) == 0x10)) &&
           (iVar5 == *(char *)(*(int *)(iVar2 + 0xb8) + 0x57))) {
          iVar3 = iVar3 + 1;
        }
        piVar1 = piVar1 + 1;
      }
      if (((iVar3 < 2) && (iVar4 != 0)) && (*(short *)(iVar4 + 0xb4) != -1)) {
        *(undefined2 *)(iVar4 + 0xb4) = 0xffff;
        (**(code **)(*DAT_803dca54 + 0x4c))(iVar5);
      }
      *(undefined2 *)(param_1 + 0xb4) = 0xffff;
    }
  }
  return;
}

