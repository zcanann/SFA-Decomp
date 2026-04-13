// Function: FUN_8003a328
// Entry: 8003a328
// Size: 336 bytes

/* WARNING: Removing unreachable block (ram,0x8003a45c) */
/* WARNING: Removing unreachable block (ram,0x8003a338) */

void FUN_8003a328(double param_1,short *param_2,char *param_3)

{
  uint uVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  psVar2 = (short *)0x0;
  iVar3 = *(int *)(param_2 + 0x28);
  if (iVar3 != 0) {
    iVar4 = 0;
    iVar5 = 0;
    for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
      if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)((int)param_2 + 0xad) + iVar4 + 1) != -1) &&
         (*(char *)(*(int *)(iVar3 + 0x10) + iVar4) == '\0')) {
        psVar2 = (short *)(*(int *)(param_2 + 0x36) + iVar5);
      }
      iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
      iVar5 = iVar5 + 0x12;
    }
  }
  if (psVar2 != (short *)0x0) {
    if (*psVar2 != 0) {
      uVar1 = *psVar2 * 3;
      *psVar2 = (short)((int)uVar1 >> 2) + (ushort)((int)uVar1 < 0 && (uVar1 & 3) != 0);
    }
    if (param_1 < (double)FLOAT_803df624) {
      param_1 = -param_1;
    }
    if ((double)FLOAT_803df664 < param_1) {
      FUN_80039c4c(param_1,param_2,param_3,(int)psVar2);
    }
    else {
      FUN_80039ef0(param_1,param_2,param_3,(int)psVar2);
    }
    *(ushort *)(param_3 + 0x1a) = *(ushort *)(param_3 + 0x1a) & 0xff;
    *(ushort *)(param_3 + 0x1a) =
         *(ushort *)(param_3 + 0x1a) | (ushort)((double)FLOAT_803df664 < param_1) << 8;
  }
  return;
}

