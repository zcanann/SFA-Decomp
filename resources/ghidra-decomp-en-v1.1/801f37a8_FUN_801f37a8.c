// Function: FUN_801f37a8
// Entry: 801f37a8
// Size: 124 bytes

void FUN_801f37a8(short *param_1)

{
  int iVar1;
  double dVar2;
  
  if (*(char *)(*(int *)(param_1 + 0x5c) + 0xc) == '\x02') {
    *param_1 = *param_1 + 0x32;
  }
  iVar1 = FUN_8002bac4();
  dVar2 = (double)FUN_800217c8((float *)(iVar1 + 0x18),(float *)(param_1 + 0xc));
  if ((double)FLOAT_803e6a80 <= dVar2) {
    FUN_8000b7dc((int)param_1,0x40);
  }
  else {
    FUN_8000bb38((uint)param_1,0x72);
  }
  return;
}

