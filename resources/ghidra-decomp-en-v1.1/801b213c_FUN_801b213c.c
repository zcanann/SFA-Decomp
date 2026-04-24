// Function: FUN_801b213c
// Entry: 801b213c
// Size: 340 bytes

/* WARNING: Removing unreachable block (ram,0x801b216c) */

void FUN_801b213c(uint param_1)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar6 = *(short **)(param_1 + 0xb8);
  if (*(char *)(psVar6 + 1) == '\x01') {
    iVar3 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803dc070 * -0x10;
    if (iVar3 < 0) {
      iVar3 = 0;
    }
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
    *(char *)(param_1 + 0x36) = (char)iVar3;
    *psVar6 = *psVar6 - (ushort)DAT_803dc070;
    if (*psVar6 < 1) {
      FUN_800201ac((int)*(short *)(iVar4 + 0x1e),1);
      *(undefined *)(psVar6 + 1) = 2;
    }
  }
  else if (*(char *)(psVar6 + 1) == '\0') {
    bVar1 = false;
    iVar3 = 0;
    iVar4 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
    if (0 < iVar4) {
      do {
        iVar5 = *(int *)(*(int *)(param_1 + 0x58) + iVar3 + 0x100);
        if ((*(short *)(iVar5 + 0x46) == 0x1d6) && (*(char *)(*(int *)(iVar5 + 0xb8) + 4) != '\0'))
        {
          bVar1 = true;
          break;
        }
        iVar3 = iVar3 + 4;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
    if (bVar1) {
      cVar2 = *(char *)((int)psVar6 + 3) + -1;
      *(char *)((int)psVar6 + 3) = cVar2;
      if (cVar2 < '\x01') {
        *(undefined *)(psVar6 + 1) = 1;
        *psVar6 = 0x1e;
        FUN_8000bb38(param_1,0x206);
      }
      else {
        FUN_8000bb38(param_1,0x207);
      }
    }
  }
  return;
}

