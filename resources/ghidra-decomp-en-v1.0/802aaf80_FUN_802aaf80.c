// Function: FUN_802aaf80
// Entry: 802aaf80
// Size: 592 bytes

void FUN_802aaf80(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5)

{
  int iVar1;
  
  if ((DAT_803de44c != 0) && ((*(byte *)(param_2 + 0x3f4) >> 6 & 1) != 0)) {
    (**(code **)(*DAT_803dca7c + 0x1c))(param_3,param_4,param_5,1,DAT_803de44c);
  }
  if (*(short *)(param_2 + 0x81c) != 0) {
    (**(code **)(*DAT_803dcab4 + 0xc))(param_1,(int)*(short *)(param_2 + 0x81c),0,100,0);
  }
  *(undefined2 *)(param_2 + 0x81c) = 0;
  if (*(char *)(param_2 + 0x8ca) == '\x01') {
    FUN_802aa8d0(param_1);
  }
  iVar1 = (**(code **)(*DAT_803dca58 + 0x34))(2);
  if (iVar1 != 0) {
    FUN_80295674(param_1,param_2);
  }
  if ((*(uint *)(param_2 + 0x360) & 0x60000) != 0) {
    DAT_803daefc = *(undefined4 *)(param_1 + 0xc);
    DAT_803daf00 = *(undefined4 *)(param_1 + 0x10);
    DAT_803daf04 = *(undefined4 *)(param_1 + 0x14);
    if ((*(uint *)(param_2 + 0x360) & 0x40000) != 0) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x427,&DAT_803daef0,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x427,&DAT_803daef0,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x427,&DAT_803daef0,0x200001,0xffffffff,0);
    }
    if ((*(uint *)(param_2 + 0x360) & 0x20000) != 0) {
      (**(code **)(*DAT_803dca98 + 0x10))
                ((double)*(float *)(param_1 + 0xc),
                 (double)((*(float *)(param_1 + 0x10) + *(float *)(param_2 + 0x838)) -
                         FLOAT_803e7f10),(double)*(float *)(param_1 + 0x14),(double)FLOAT_803e7ffc,
                 param_1);
      (**(code **)(*DAT_803dca98 + 0x14))
                ((double)*(float *)(param_1 + 0xc),
                 (double)(*(float *)(param_1 + 0x10) + *(float *)(param_2 + 0x838)),
                 (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e80e4,0,2);
      *(uint *)(param_2 + 0x360) = *(uint *)(param_2 + 0x360) & 0xfffdffff;
    }
  }
  return;
}

