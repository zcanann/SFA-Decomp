// Function: FUN_801b1bdc
// Entry: 801b1bdc
// Size: 296 bytes

void FUN_801b1bdc(int param_1)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  
  pcVar6 = *(char **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  cVar1 = *pcVar6;
  if (cVar1 != '\x01') {
    if (cVar1 < '\x01') {
      if (-1 < cVar1) {
        if (*(char *)(*(int *)(param_1 + 0x54) + 0xb0) != '\x01') {
          FUN_800359cc(param_1,*(int *)(param_1 + 0x54),1);
        }
        bVar2 = false;
        iVar4 = 0;
        iVar3 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
        if (0 < iVar3) {
          do {
            if (*(short *)(*(int *)(*(int *)(param_1 + 0x58) + iVar4 + 0x100) + 0x46) == 399) {
              bVar2 = true;
              break;
            }
            iVar4 = iVar4 + 4;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
        if (bVar2) {
          FUN_800201ac((int)*(short *)(iVar5 + 0x1e),1);
          if (*(char *)(*(int *)(param_1 + 0x54) + 0xb0) != '\x02') {
            FUN_800359cc(param_1,*(int *)(param_1 + 0x54),2);
          }
          *pcVar6 = '\x02';
        }
      }
    }
    else if ((cVar1 < '\x03') && (*(char *)(*(int *)(param_1 + 0x54) + 0xb0) != '\x02')) {
      FUN_800359cc(param_1,*(int *)(param_1 + 0x54),2);
    }
  }
  return;
}

