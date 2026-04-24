// Function: FUN_80223bc4
// Entry: 80223bc4
// Size: 112 bytes

undefined4 FUN_80223bc4(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = FUN_8002b9ec();
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(float *)(param_2 + 0x2a0) = FLOAT_803e6d10;
    FUN_800217c0((double)(*(float *)(param_1 + 0xc) - *(float *)(iVar1 + 0xc)),
                 (double)(*(float *)(param_1 + 0x14) - *(float *)(iVar1 + 0x14)));
  }
  return 0;
}

