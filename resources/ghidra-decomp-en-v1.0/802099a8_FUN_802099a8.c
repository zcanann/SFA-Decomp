// Function: FUN_802099a8
// Entry: 802099a8
// Size: 208 bytes

void FUN_802099a8(int param_1)

{
  int iVar1;
  int *piVar2;
  
  if (param_1 != 0) {
    piVar2 = *(int **)(param_1 + 0xb8);
    if (FLOAT_803e64e0 <= (float)piVar2[1]) {
      iVar1 = FUN_8001ffb4(0x5e5);
      if (*piVar2 != 0) {
        FUN_8008f904();
      }
      if (iVar1 == 0) {
        if (FLOAT_803e64e8 <= (float)piVar2[1]) {
          piVar2[1] = (int)FLOAT_803e64e4;
        }
      }
      else if (FLOAT_803e64e0 +
               (float)((double)CONCAT44(0x43300000,(int)*(short *)((int)piVar2 + 0x16) ^ 0x80000000)
                      - DOUBLE_803e64f0) <= (float)piVar2[1]) {
        piVar2[1] = (int)FLOAT_803e64e4;
      }
    }
  }
  return;
}

