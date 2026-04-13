// Function: FUN_802be820
// Entry: 802be820
// Size: 204 bytes

void FUN_802be820(short *param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  if (in_r8 == -1) {
    FUN_8003b9ec((int)param_1);
    FUN_80038524(param_1,0xb,(float *)(iVar1 + 0x1438),(undefined4 *)(iVar1 + 0x143c),
                 (float *)(iVar1 + 0x1440),0);
    FUN_80038378(param_1,3,4,(float *)(iVar1 + 0xb18));
  }
  else if (in_r8 != '\0') {
    FUN_8003b9ec((int)param_1);
    FUN_80038524(param_1,0xb,(float *)(iVar1 + 0x1438),(undefined4 *)(iVar1 + 0x143c),
                 (float *)(iVar1 + 0x1440),0);
    FUN_80038378(param_1,3,4,(float *)(iVar1 + 0xb18));
    FUN_80115088(param_1,iVar1 + 0x3ec,0);
  }
  return;
}

