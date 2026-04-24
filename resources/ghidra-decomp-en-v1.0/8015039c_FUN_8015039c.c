// Function: FUN_8015039c
// Entry: 8015039c
// Size: 288 bytes

void FUN_8015039c(int param_1,int param_2)

{
  int iVar1;
  double dVar2;
  
  if ((*(ushort *)(param_2 + 0x2f8) & 0x200) != 0) {
    FUN_8000bb18(param_1,899);
    iVar1 = FUN_8002b9ec();
    if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
      dVar2 = (double)FUN_80021704(param_1 + 0x18,iVar1 + 0x18);
      if (dVar2 <= (double)FLOAT_803e2760) {
        FUN_80014aa0((double)(FLOAT_803e2744 *
                             (FLOAT_803e2748 - (float)(dVar2 / (double)FLOAT_803e2760))));
      }
      FUN_8000e718((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                   (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e2760,(double)FLOAT_803e2764)
      ;
    }
  }
  if ((*(ushort *)(param_2 + 0x2f8) & 0x40) != 0) {
    FUN_8000bb18(param_1,0x19);
  }
  if ((*(ushort *)(param_2 + 0x2f8) & 0x1000) != 0) {
    FUN_8000bb18(param_1,599);
  }
  if ((*(ushort *)(param_2 + 0x2f8) & 1) != 0) {
    FUN_8000bb18(param_1,0x12);
  }
  if ((*(ushort *)(param_2 + 0x2f8) & 0x80) != 0) {
    FUN_8000bb18(param_1,0x15);
  }
  return;
}

