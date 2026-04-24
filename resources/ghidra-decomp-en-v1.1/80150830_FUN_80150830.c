// Function: FUN_80150830
// Entry: 80150830
// Size: 288 bytes

void FUN_80150830(uint param_1,int param_2)

{
  int iVar1;
  double dVar2;
  
  if ((*(ushort *)(param_2 + 0x2f8) & 0x200) != 0) {
    FUN_8000bb38(param_1,899);
    iVar1 = FUN_8002bac4();
    if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
      dVar2 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18));
      if (dVar2 <= (double)FLOAT_803e33f8) {
        FUN_80014acc((double)(FLOAT_803e33dc *
                             (FLOAT_803e33e0 - (float)(dVar2 / (double)FLOAT_803e33f8))));
      }
      FUN_8000e738((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                   (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e33f8,(double)FLOAT_803e33fc)
      ;
    }
  }
  if ((*(ushort *)(param_2 + 0x2f8) & 0x40) != 0) {
    FUN_8000bb38(param_1,0x19);
  }
  if ((*(ushort *)(param_2 + 0x2f8) & 0x1000) != 0) {
    FUN_8000bb38(param_1,599);
  }
  if ((*(ushort *)(param_2 + 0x2f8) & 1) != 0) {
    FUN_8000bb38(param_1,0x12);
  }
  if ((*(ushort *)(param_2 + 0x2f8) & 0x80) != 0) {
    FUN_8000bb38(param_1,0x15);
  }
  return;
}

