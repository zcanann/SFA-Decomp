// Function: FUN_801a35e8
// Entry: 801a35e8
// Size: 336 bytes

void FUN_801a35e8(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  if (*(char *)(iVar3 + 0x6e4) != '\x02') {
    if (*(char *)(iVar3 + 0x6e4) == '\0') {
      iVar1 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x40));
      if (iVar1 != 0) {
        FUN_801a2e80(param_1,iVar5,0,iVar3);
        if (*(uint *)(iVar3 + 0x6d0) != 0) {
          FUN_8000bb18(param_1,*(uint *)(iVar3 + 0x6d0) & 0xffff);
        }
        *(undefined *)(iVar3 + 0x6e4) = 1;
        *(undefined *)(param_1 + 0x36) = 0;
      }
    }
    else {
      iVar4 = 0;
      iVar1 = iVar3;
      do {
        if (*(int *)(iVar1 + 0x690) != 0) {
          iVar2 = (**(code **)(**(int **)(*(int *)(iVar1 + 0x690) + 0x68) + 0x20))();
          if (iVar2 != 1) {
            if (iVar2 < 1) {
              if (-1 < iVar2) {
                FUN_800200e8((int)*(short *)(iVar5 + 0x3e),1);
                if ((*(uint *)(iVar3 + 0x6cc) & 1 << iVar4) == 0) {
                  *(uint *)(iVar3 + 0x6cc) = *(uint *)(iVar3 + 0x6cc) | 1 << iVar4;
                }
              }
            }
            else if (iVar2 < 3) {
              FUN_800200e8((int)*(short *)(iVar5 + 0x3e),1);
              FUN_8002cbc4(*(undefined4 *)(iVar1 + 0x690));
              *(undefined4 *)(iVar1 + 0x690) = 0;
            }
          }
        }
        iVar1 = iVar1 + 4;
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0xf);
    }
  }
  return;
}

