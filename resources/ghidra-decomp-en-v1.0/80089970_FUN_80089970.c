// Function: FUN_80089970
// Entry: 80089970
// Size: 224 bytes

void FUN_80089970(int param_1)

{
  int iVar1;
  
  if (DAT_803dd144 != 0) {
    iVar1 = DAT_803dd12c + param_1 * 0xa4;
    FUN_8001dc90((double)*(float *)(iVar1 + 0x90),(double)*(float *)(iVar1 + 0x94),
                 (double)*(float *)(iVar1 + 0x98));
    iVar1 = DAT_803dd12c + param_1 * 0xa4;
    FUN_8001daf0(DAT_803dd144,*(undefined *)(iVar1 + 0x78),*(undefined *)(iVar1 + 0x79),
                 *(undefined *)(iVar1 + 0x7a),0xff);
  }
  if (DAT_803dd168 != 0) {
    iVar1 = DAT_803dd12c + param_1 * 0xa4;
    FUN_8001dc90((double)*(float *)(iVar1 + 0x9c),(double)*(float *)(iVar1 + 0xa0),
                 (double)*(float *)(iVar1 + 0xa4));
    iVar1 = DAT_803dd12c + param_1 * 0xa4;
    FUN_8001daf0(DAT_803dd168,*(undefined *)(iVar1 + 0x80),*(undefined *)(iVar1 + 0x81),
                 *(undefined *)(iVar1 + 0x82),0xff);
  }
  iVar1 = DAT_803dd12c + param_1 * 0xa4;
  FUN_8001efe0(0,*(undefined *)(iVar1 + 0x88),*(undefined *)(iVar1 + 0x89),
               *(undefined *)(iVar1 + 0x8a));
  return;
}

