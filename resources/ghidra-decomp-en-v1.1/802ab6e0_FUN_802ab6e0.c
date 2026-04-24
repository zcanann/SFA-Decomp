// Function: FUN_802ab6e0
// Entry: 802ab6e0
// Size: 592 bytes

void FUN_802ab6e0(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5)

{
  int iVar1;
  
  if ((DAT_803df0cc != 0) && ((*(byte *)(param_2 + 0x3f4) >> 6 & 1) != 0)) {
    (**(code **)(*DAT_803dd6fc + 0x1c))(param_3,param_4,param_5,1,DAT_803df0cc);
  }
  if (*(short *)(param_2 + 0x81c) != 0) {
    (**(code **)(*DAT_803dd734 + 0xc))(param_1,(int)*(short *)(param_2 + 0x81c),0,100,0);
  }
  *(undefined2 *)(param_2 + 0x81c) = 0;
  if (*(char *)(param_2 + 0x8ca) == '\x01') {
    FUN_802ab030(param_1);
  }
  iVar1 = (**(code **)(*DAT_803dd6d8 + 0x34))(2);
  if (iVar1 != 0) {
    FUN_80295dd4();
  }
  if ((*(uint *)(param_2 + 0x360) & 0x60000) != 0) {
    DAT_803dbb5c = *(undefined4 *)(param_1 + 0xc);
    DAT_803dbb60 = *(undefined4 *)(param_1 + 0x10);
    DAT_803dbb64 = *(undefined4 *)(param_1 + 0x14);
    if ((*(uint *)(param_2 + 0x360) & 0x40000) != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x427,&DAT_803dbb50,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x427,&DAT_803dbb50,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x427,&DAT_803dbb50,0x200001,0xffffffff,0);
    }
    if ((*(uint *)(param_2 + 0x360) & 0x20000) != 0) {
      (**(code **)(*DAT_803dd718 + 0x10))
                ((double)*(float *)(param_1 + 0xc),
                 (double)((*(float *)(param_1 + 0x10) + *(float *)(param_2 + 0x838)) -
                         FLOAT_803e8ba8),(double)*(float *)(param_1 + 0x14),(double)FLOAT_803e8c94,
                 param_1);
      (**(code **)(*DAT_803dd718 + 0x14))
                ((double)*(float *)(param_1 + 0xc),
                 (double)(*(float *)(param_1 + 0x10) + *(float *)(param_2 + 0x838)),
                 (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e8d7c,0,2);
      *(uint *)(param_2 + 0x360) = *(uint *)(param_2 + 0x360) & 0xfffdffff;
    }
  }
  return;
}

