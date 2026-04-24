// Function: FUN_801c5474
// Entry: 801c5474
// Size: 372 bytes

void FUN_801c5474(int param_1)

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
  
  if ((*(int *)(param_1 + 0x4c) != 0) && (*(short *)(*(int *)(param_1 + 0x4c) + 0x18) != -1)) {
    uStack28 = (uint)DAT_803db411;
    local_20 = 0x43300000;
    local_24 = (**(code **)(*DAT_803dca54 + 0x14))
                         ((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e4f70));
    if ((local_24 != 0) && (*(short *)(param_1 + 0xb4) == -2)) {
      iVar4 = (int)*(char *)(*(int *)(param_1 + 0xb8) + 0x57);
      iVar5 = 0;
      piVar1 = (int *)FUN_8002e0fc(&local_24,&local_28);
      iVar3 = 0;
      for (local_24 = 0; local_24 < local_28; local_24 = local_24 + 1) {
        iVar2 = *piVar1;
        if (*(short *)(iVar2 + 0xb4) == iVar4) {
          iVar5 = iVar2;
        }
        if (((*(short *)(iVar2 + 0xb4) == -2) && (*(short *)(iVar2 + 0x44) == 0x10)) &&
           (iVar4 == *(char *)(*(int *)(iVar2 + 0xb8) + 0x57))) {
          iVar3 = iVar3 + 1;
        }
        piVar1 = piVar1 + 1;
      }
      if (((iVar3 < 2) && (iVar5 != 0)) && (*(short *)(iVar5 + 0xb4) != -1)) {
        *(undefined2 *)(iVar5 + 0xb4) = 0xffff;
        (**(code **)(*DAT_803dca54 + 0x4c))(iVar4);
      }
      *(undefined2 *)(param_1 + 0xb4) = 0xffff;
      FUN_8002cbc4(param_1);
    }
  }
  return;
}

