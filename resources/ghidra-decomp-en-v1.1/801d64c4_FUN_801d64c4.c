// Function: FUN_801d64c4
// Entry: 801d64c4
// Size: 132 bytes

void FUN_801d64c4(short *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  FUN_8003b9ec((int)param_1);
  FUN_80115088(param_1,iVar2,0);
  iVar1 = 0;
  do {
    FUN_80038524(param_1,iVar1,(float *)(iVar2 + 0x8e0),(undefined4 *)(iVar2 + 0x8e4),
                 (float *)(iVar2 + 0x8e8),0);
    iVar2 = iVar2 + 0xc;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  return;
}

