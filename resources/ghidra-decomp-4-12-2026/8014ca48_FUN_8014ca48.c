// Function: FUN_8014ca48
// Entry: 8014ca48
// Size: 108 bytes

double FUN_8014ca48(int param_1)

{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (iVar1 == 0) {
    dVar2 = (double)FLOAT_803e31fc;
  }
  else if ((*(ushort *)(iVar1 + 0x2b2) == 0) || (*(ushort *)(iVar1 + 0x2b0) == 0)) {
    dVar2 = (double)FLOAT_803e31fc;
  }
  else {
    dVar2 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar1 + 0x2b0)) -
                            DOUBLE_803e3278) /
                    (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar1 + 0x2b2)) -
                           DOUBLE_803e3278));
  }
  return dVar2;
}

