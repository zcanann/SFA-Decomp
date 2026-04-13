// Function: FUN_801f9e3c
// Entry: 801f9e3c
// Size: 312 bytes

void FUN_801f9e3c(int param_1)

{
  uint uVar1;
  ushort uVar2;
  int iVar3;
  short *psVar4;
  short local_18 [6];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(byte *)(iVar3 + 0x18) < 4) {
    uVar1 = FUN_80020078(0xe1a);
    local_18[0] = (short)uVar1;
    uVar1 = FUN_80020078(0xe19);
    local_18[1] = (short)uVar1;
    uVar1 = FUN_80020078(0xe17);
    local_18[2] = (short)uVar1;
    uVar1 = FUN_80020078(0xe18);
    local_18[3] = (short)uVar1;
    psVar4 = local_18 + (short)(ushort)*(byte *)(iVar3 + 0x18);
    for (uVar2 = (ushort)*(byte *)(iVar3 + 0x18); (short)uVar2 < 4; uVar2 = uVar2 + 1) {
      if (uVar2 == *(byte *)(iVar3 + 0x18)) {
        if ((*psVar4 != 0) &&
           (*(byte *)(iVar3 + 0x18) = *(byte *)(iVar3 + 0x18) + 1, *(char *)(iVar3 + 0x18) == '\x04'
           )) {
          FUN_800201ac(0xe1b,1);
        }
      }
      else if (*psVar4 != 0) {
        *(undefined *)(iVar3 + 0x18) = 0;
        FUN_800201ac(0xe1a,0);
        FUN_800201ac(0xe19,0);
        FUN_800201ac(0xe17,0);
        FUN_800201ac(0xe18,0);
        return;
      }
      psVar4 = psVar4 + 1;
    }
  }
  return;
}

