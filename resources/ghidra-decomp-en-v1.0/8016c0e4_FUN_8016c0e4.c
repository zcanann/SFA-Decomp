// Function: FUN_8016c0e4
// Entry: 8016c0e4
// Size: 596 bytes

void FUN_8016c0e4(int param_1)

{
  byte bVar1;
  int *piVar2;
  char cVar4;
  undefined4 uVar3;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int local_18;
  int local_14;
  
  iVar8 = *(int *)(param_1 + 0xb8);
  if ((*(int *)(param_1 + 0x4c) != 0) && (*(short *)(*(int *)(param_1 + 0x4c) + 0x18) != -1)) {
    local_14 = (**(code **)(*DAT_803dca54 + 0x14))((double)FLOAT_803db414);
    if ((local_14 != 0) && (*(short *)(param_1 + 0xb4) == -2)) {
      iVar7 = (int)*(char *)(iVar8 + 0x57);
      iVar9 = 0;
      piVar2 = (int *)FUN_8002e0fc(&local_14,&local_18);
      iVar6 = 0;
      for (local_14 = 0; local_14 < local_18; local_14 = local_14 + 1) {
        iVar5 = *piVar2;
        if (*(short *)(iVar5 + 0xb4) == iVar7) {
          iVar9 = iVar5;
        }
        if (((*(short *)(iVar5 + 0xb4) == -2) && (*(short *)(iVar5 + 0x44) == 0x10)) &&
           (iVar8 = *(int *)(iVar5 + 0xb8), iVar7 == *(char *)(iVar8 + 0x57))) {
          iVar6 = iVar6 + 1;
        }
        piVar2 = piVar2 + 1;
      }
      if (((iVar6 < 2) && (iVar9 != 0)) && (*(short *)(iVar9 + 0xb4) != -1)) {
        *(undefined2 *)(iVar9 + 0xb4) = 0xffff;
        (**(code **)(*DAT_803dca54 + 0x4c))(iVar7);
      }
      *(undefined2 *)(param_1 + 0xb4) = 0xffff;
      *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    }
    if (*(short *)(param_1 + 0x46) == 0x774) {
      for (iVar9 = 0; iVar9 < (int)(uint)*(byte *)(iVar8 + 0x8b); iVar9 = iVar9 + 1) {
        bVar1 = *(byte *)(iVar8 + iVar9 + 0x81);
        if (bVar1 == 0xb) {
          if (*(char *)(param_1 + 0xeb) != '\0') {
            FUN_8002cbc4(*(undefined4 *)(param_1 + 200));
            FUN_80037cb0(param_1,*(undefined4 *)(param_1 + 200));
          }
        }
        else if (((bVar1 < 0xb) && (9 < bVar1)) && (cVar4 = FUN_8002e04c(), cVar4 != '\0')) {
          uVar3 = FUN_8002bdf4(0x18,0x69);
          uVar3 = FUN_8002df90(uVar3,4,0xffffffff,0xffffffff,0);
          FUN_80037d2c(param_1,uVar3,0);
          FUN_80030334((double)FLOAT_803e322c,uVar3,0,0);
          FUN_8002fa48((double)FLOAT_803e3228,(double)FLOAT_803db414,uVar3,0);
        }
      }
    }
  }
  return;
}

