// Function: FUN_8011175c
// Entry: 8011175c
// Size: 284 bytes

void FUN_8011175c(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xa4);
  if (param_2 != 1) {
    DAT_803a502c = *(undefined4 *)(iVar1 + 0x18);
    DAT_803a5030 = *(undefined4 *)(iVar1 + 0x1c);
    DAT_803a5034 = *(undefined4 *)(iVar1 + 0x20);
  }
  DAT_803a5050 = FLOAT_803e2824;
  DAT_803a5054 = FLOAT_803e2840;
  DAT_803a5058 = FLOAT_803e2844;
  FUN_80247e94((float *)(iVar1 + 0x18),&DAT_803a5050,(float *)(param_1 + 0x18));
  DAT_803a507e = 1;
  DAT_803a5064 = FLOAT_803e2848;
  DAT_803a5068 = FLOAT_803e284c;
  DAT_803a506c = FLOAT_803e2850;
  DAT_803a5044 = FLOAT_803e2854;
  DAT_803a5048 = FLOAT_803e2858;
  DAT_803a504c = FLOAT_803e2824;
  DAT_803a5060 = FLOAT_803e285c;
  DAT_803a505c = FLOAT_803e285c;
  DAT_803a507b = 0x5a;
  DAT_803a507a = 100;
  DAT_803a5028 = FLOAT_803e2824;
  DAT_803a5024 = FLOAT_803e2824;
  DAT_803a5020 = FLOAT_803e2824;
  *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(iVar1 + 0x18);
  *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(iVar1 + 0x1c);
  *(float *)(param_1 + 0x20) = *(float *)(iVar1 + 0x20) + DAT_803a5058;
  return;
}

