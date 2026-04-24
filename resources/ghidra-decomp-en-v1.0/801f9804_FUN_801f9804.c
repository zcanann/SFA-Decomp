// Function: FUN_801f9804
// Entry: 801f9804
// Size: 312 bytes

void FUN_801f9804(int param_1)

{
  ushort uVar1;
  int iVar2;
  short *psVar3;
  short local_18 [6];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(byte *)(iVar2 + 0x18) < 4) {
    local_18[0] = FUN_8001ffb4(0xe1a);
    local_18[1] = FUN_8001ffb4(0xe19);
    local_18[2] = FUN_8001ffb4(0xe17);
    local_18[3] = FUN_8001ffb4(0xe18);
    psVar3 = local_18 + (short)(ushort)*(byte *)(iVar2 + 0x18);
    for (uVar1 = (ushort)*(byte *)(iVar2 + 0x18); (short)uVar1 < 4; uVar1 = uVar1 + 1) {
      if (uVar1 == *(byte *)(iVar2 + 0x18)) {
        if ((*psVar3 != 0) &&
           (*(byte *)(iVar2 + 0x18) = *(byte *)(iVar2 + 0x18) + 1, *(char *)(iVar2 + 0x18) == '\x04'
           )) {
          FUN_800200e8(0xe1b,1);
        }
      }
      else if (*psVar3 != 0) {
        *(undefined *)(iVar2 + 0x18) = 0;
        FUN_800200e8(0xe1a,0);
        FUN_800200e8(0xe19,0);
        FUN_800200e8(0xe17,0);
        FUN_800200e8(0xe18,0);
        return;
      }
      psVar3 = psVar3 + 1;
    }
  }
  return;
}

