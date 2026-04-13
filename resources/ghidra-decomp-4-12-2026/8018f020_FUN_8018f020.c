// Function: FUN_8018f020
// Entry: 8018f020
// Size: 384 bytes

void FUN_8018f020(undefined4 param_1,undefined4 param_2,int param_3)

{
  short *psVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  psVar1 = (short *)FUN_80286838();
  iVar3 = *(int *)(psVar1 + 0x5c);
  iVar5 = *(int *)(psVar1 + 0x26);
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    iVar4 = iVar2 + 0x81;
    if (*(char *)(param_3 + iVar4) == '\x01') {
      FUN_8018ec40();
    }
    if (*(char *)(param_3 + iVar4) == '\x02') {
      *(char *)(iVar3 + 0x1c) = '\x01' - *(char *)(iVar3 + 0x1c);
    }
    *(undefined *)(param_3 + iVar4) = 0;
  }
  if (*(char *)(iVar3 + 0x1c) != '\0') {
    if (*(char *)(iVar5 + 0x27) == '\x7f') {
      *psVar1 = *psVar1 + (ushort)DAT_803dc070 * 10;
    }
    else {
      *psVar1 = *psVar1 + (short)*(char *)(iVar5 + 0x27) * (ushort)DAT_803dc070 * 100;
    }
    if (*(char *)(iVar5 + 0x26) == '\x7f') {
      psVar1[1] = psVar1[1] + (ushort)DAT_803dc070 * 10;
    }
    else {
      psVar1[1] = psVar1[1] + (short)*(char *)(iVar5 + 0x26) * (ushort)DAT_803dc070 * 100;
    }
    if (*(char *)(iVar5 + 0x25) == '\x7f') {
      psVar1[2] = psVar1[2] + (ushort)DAT_803dc070 * 10;
    }
    else {
      psVar1[2] = psVar1[2] + (short)*(char *)(iVar5 + 0x25) * (ushort)DAT_803dc070 * 100;
    }
    FUN_8018ec40();
  }
  FUN_80286884();
  return;
}

