// Function: FUN_801fc55c
// Entry: 801fc55c
// Size: 168 bytes

void FUN_801fc55c(int param_1)

{
  int iVar1;
  short *psVar2;
  
  if (*(short *)(param_1 + 0x46) == 999) {
    psVar2 = *(short **)(param_1 + 0xb8);
    if ((-1 < *(char *)(psVar2 + 1)) && (iVar1 = FUN_8001ffb4((int)*psVar2), iVar1 != 0)) {
      FUN_8000bb18(0,0x109);
      FUN_8000bb18(param_1,0x10d);
      FUN_8000bb18(param_1,0x494);
      FUN_8002b884(param_1,1);
      *(byte *)(psVar2 + 1) = *(byte *)(psVar2 + 1) & 0x7f | 0x80;
    }
  }
  else {
    FUN_801fc378();
  }
  return;
}

