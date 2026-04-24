// Function: FUN_80060898
// Entry: 80060898
// Size: 232 bytes

void FUN_80060898(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar1 = FUN_80286834();
  iVar3 = 0;
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(iVar1 + 0xa2); iVar6 = iVar6 + 1) {
    iVar5 = *(int *)(iVar1 + 100) + iVar3;
    iVar4 = iVar5;
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(iVar5 + 0x41); iVar2 = iVar2 + 1) {
      if (*(int *)(iVar4 + 0x24) == -1) {
        *(undefined4 *)(iVar4 + 0x24) = 0;
      }
      else {
        *(undefined4 *)(iVar4 + 0x24) =
             *(undefined4 *)(*(int *)(iVar1 + 0x54) + *(int *)(iVar4 + 0x24) * 4);
        if (*(byte *)(iVar4 + 0x29) != 0) {
          FUN_80056924(*(int *)(iVar4 + 0x24),0,(uint)*(byte *)(iVar4 + 0x29));
        }
      }
      *(undefined *)(iVar4 + 0x2a) = 0xff;
      iVar4 = iVar4 + 8;
    }
    if (*(int *)(iVar5 + 0x34) == -1) {
      *(undefined4 *)(iVar5 + 0x34) = 0;
    }
    else {
      *(undefined4 *)(iVar5 + 0x34) =
           *(undefined4 *)(*(int *)(iVar1 + 0x54) + *(int *)(iVar5 + 0x34) * 4);
    }
    iVar3 = iVar3 + 0x44;
  }
  FUN_80286880();
  return;
}

