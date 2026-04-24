// Function: FUN_801b1b88
// Entry: 801b1b88
// Size: 340 bytes

/* WARNING: Removing unreachable block (ram,0x801b1bb8) */

void FUN_801b1b88(int param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  bool bVar5;
  short *psVar6;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  psVar6 = *(short **)(param_1 + 0xb8);
  if (*(char *)(psVar6 + 1) == '\x01') {
    iVar2 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803db410 * -0x10;
    if (iVar2 < 0) {
      iVar2 = 0;
    }
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
    *(char *)(param_1 + 0x36) = (char)iVar2;
    *psVar6 = *psVar6 - (ushort)DAT_803db410;
    if (*psVar6 < 1) {
      FUN_800200e8((int)*(short *)(iVar3 + 0x1e),1);
      *(undefined *)(psVar6 + 1) = 2;
    }
  }
  else if (*(char *)(psVar6 + 1) == '\0') {
    bVar5 = false;
    iVar2 = 0;
    iVar3 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
    if (0 < iVar3) {
      do {
        iVar4 = *(int *)(*(int *)(param_1 + 0x58) + iVar2 + 0x100);
        if ((*(short *)(iVar4 + 0x46) == 0x1d6) && (*(char *)(*(int *)(iVar4 + 0xb8) + 4) != '\0'))
        {
          bVar5 = true;
          break;
        }
        iVar2 = iVar2 + 4;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    if (bVar5) {
      cVar1 = *(char *)((int)psVar6 + 3) + -1;
      *(char *)((int)psVar6 + 3) = cVar1;
      if (cVar1 < '\x01') {
        *(undefined *)(psVar6 + 1) = 1;
        *psVar6 = 0x1e;
        FUN_8000bb18(param_1,0x206);
      }
      else {
        FUN_8000bb18(param_1,0x207);
      }
    }
  }
  return;
}

