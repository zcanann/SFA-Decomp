// Function: FUN_8003a230
// Entry: 8003a230
// Size: 336 bytes

/* WARNING: Removing unreachable block (ram,0x8003a364) */

void FUN_8003a230(double param_1,int param_2,int param_3)

{
  uint uVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  psVar2 = (short *)0x0;
  iVar3 = *(int *)(param_2 + 0x50);
  if (iVar3 != 0) {
    iVar4 = 0;
    iVar5 = 0;
    for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
      if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)(param_2 + 0xad) + iVar4 + 1) != -1) &&
         (*(char *)(*(int *)(iVar3 + 0x10) + iVar4) == '\0')) {
        psVar2 = (short *)(*(int *)(param_2 + 0x6c) + iVar5);
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
    if (param_1 < (double)FLOAT_803de9a4) {
      param_1 = -param_1;
    }
    if ((double)FLOAT_803de9e4 < param_1) {
      FUN_80039b54(param_1,param_2,param_3);
    }
    else {
      FUN_80039df8(param_1,param_2,param_3);
    }
    *(ushort *)(param_3 + 0x1a) = *(ushort *)(param_3 + 0x1a) & 0xff;
    *(ushort *)(param_3 + 0x1a) =
         *(ushort *)(param_3 + 0x1a) | (ushort)((double)FLOAT_803de9e4 < param_1) << 8;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

