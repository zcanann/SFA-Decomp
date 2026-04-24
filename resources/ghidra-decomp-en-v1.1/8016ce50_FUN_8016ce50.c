// Function: FUN_8016ce50
// Entry: 8016ce50
// Size: 572 bytes

void FUN_8016ce50(int param_1)

{
  byte bVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int local_38;
  int local_34;
  undefined auStack_30 [12];
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  iVar6 = *(int *)(param_1 + 0xb8);
  if ((*(int *)(param_1 + 0x4c) != 0) && (*(short *)(*(int *)(param_1 + 0x4c) + 0x18) != -1)) {
    for (local_38 = 0; local_38 < (int)(uint)*(byte *)(iVar6 + 0x8b); local_38 = local_38 + 1) {
      bVar1 = *(byte *)(iVar6 + local_38 + 0x81);
      if (bVar1 == 3) {
        *(uint *)(param_1 + 0xf8) = *(uint *)(param_1 + 0xf8) ^ 4;
      }
      else if (bVar1 < 3) {
        if (bVar1 == 1) {
          *(uint *)(param_1 + 0xf8) = *(uint *)(param_1 + 0xf8) ^ 1;
        }
        else if (bVar1 != 0) {
          *(uint *)(param_1 + 0xf8) = *(uint *)(param_1 + 0xf8) ^ 2;
        }
      }
      else if (bVar1 < 5) {
        local_24 = *(undefined4 *)(param_1 + 0xc);
        local_20 = *(undefined4 *)(param_1 + 0x10);
        local_1c = *(undefined4 *)(param_1 + 0x14);
        iVar4 = 3;
        do {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7fe,auStack_30,0x200001,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    local_38 = (**(code **)(*DAT_803dd6d4 + 0x14))((double)FLOAT_803dc074,param_1);
    if ((local_38 != 0) && (*(short *)(param_1 + 0xb4) == -2)) {
      iVar5 = (int)*(char *)(iVar6 + 0x57);
      iVar6 = 0;
      piVar2 = (int *)FUN_8002e1f4(&local_38,&local_34);
      iVar4 = 0;
      for (local_38 = 0; local_38 < local_34; local_38 = local_38 + 1) {
        iVar3 = *piVar2;
        if (*(short *)(iVar3 + 0xb4) == iVar5) {
          iVar6 = iVar3;
        }
        if (((*(short *)(iVar3 + 0xb4) == -2) && (*(short *)(iVar3 + 0x44) == 0x10)) &&
           (iVar5 == *(char *)(*(int *)(iVar3 + 0xb8) + 0x57))) {
          iVar4 = iVar4 + 1;
        }
        piVar2 = piVar2 + 1;
      }
      if (((iVar4 < 2) && (iVar6 != 0)) && (*(short *)(iVar6 + 0xb4) != -1)) {
        *(undefined2 *)(iVar6 + 0xb4) = 0xffff;
        (**(code **)(*DAT_803dd6d4 + 0x4c))(iVar5);
      }
      *(undefined2 *)(param_1 + 0xb4) = 0xffff;
    }
  }
  return;
}

