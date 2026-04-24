// Function: FUN_801b1628
// Entry: 801b1628
// Size: 296 bytes

void FUN_801b1628(int param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  bool bVar4;
  int iVar5;
  char *pcVar6;
  
  pcVar6 = *(char **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  cVar1 = *pcVar6;
  if (cVar1 != '\x01') {
    if (cVar1 < '\x01') {
      if (-1 < cVar1) {
        if (*(char *)(*(int *)(param_1 + 0x54) + 0xb0) != '\x01') {
          FUN_800358d4(param_1,*(int *)(param_1 + 0x54),1);
        }
        bVar4 = false;
        iVar3 = 0;
        iVar2 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
        if (0 < iVar2) {
          do {
            if (*(short *)(*(int *)(*(int *)(param_1 + 0x58) + iVar3 + 0x100) + 0x46) == 399) {
              bVar4 = true;
              break;
            }
            iVar3 = iVar3 + 4;
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
        }
        if (bVar4) {
          FUN_800200e8((int)*(short *)(iVar5 + 0x1e),1);
          if (*(char *)(*(int *)(param_1 + 0x54) + 0xb0) != '\x02') {
            FUN_800358d4(param_1,*(int *)(param_1 + 0x54),2);
          }
          *pcVar6 = '\x02';
        }
      }
    }
    else if ((cVar1 < '\x03') && (*(char *)(*(int *)(param_1 + 0x54) + 0xb0) != '\x02')) {
      FUN_800358d4(param_1,*(int *)(param_1 + 0x54),2);
    }
  }
  return;
}

