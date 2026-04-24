// Function: FUN_801114c0
// Entry: 801114c0
// Size: 284 bytes

void FUN_801114c0(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xa4);
  if (param_2 != 1) {
    DAT_803a43cc = *(undefined4 *)(iVar1 + 0x18);
    DAT_803a43d0 = *(undefined4 *)(iVar1 + 0x1c);
    DAT_803a43d4 = *(undefined4 *)(iVar1 + 0x20);
  }
  DAT_803a43f0 = FLOAT_803e1ba4;
  DAT_803a43f4 = FLOAT_803e1bc0;
  DAT_803a43f8 = FLOAT_803e1bc4;
  FUN_80247730(iVar1 + 0x18,&DAT_803a43f0,param_1 + 0x18);
  DAT_803a441e = 1;
  DAT_803a4404 = FLOAT_803e1bc8;
  DAT_803a4408 = FLOAT_803e1bcc;
  DAT_803a440c = FLOAT_803e1bd0;
  DAT_803a43e4 = FLOAT_803e1bd4;
  DAT_803a43e8 = FLOAT_803e1bd8;
  DAT_803a43ec = FLOAT_803e1ba4;
  DAT_803a4400 = FLOAT_803e1bdc;
  DAT_803a43fc = FLOAT_803e1bdc;
  DAT_803a441b = 0x5a;
  DAT_803a441a = 100;
  DAT_803a43c8 = FLOAT_803e1ba4;
  DAT_803a43c4 = FLOAT_803e1ba4;
  DAT_803a43c0 = FLOAT_803e1ba4;
  *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(iVar1 + 0x18);
  *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(iVar1 + 0x1c);
  *(float *)(param_1 + 0x20) = *(float *)(iVar1 + 0x20) + DAT_803a43f8;
  return;
}

