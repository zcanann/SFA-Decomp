// Function: FUN_80233964
// Entry: 80233964
// Size: 308 bytes

void FUN_80233964(int param_1)

{
  int iVar1;
  char *pcVar2;
  double dVar3;
  
  pcVar2 = *(char **)(param_1 + 0xb8);
  iVar1 = FUN_8022d768();
  if (iVar1 == 0) {
    iVar1 = FUN_8002b9ec();
  }
  dVar3 = (double)FUN_80021704(param_1 + 0x18,iVar1 + 0x18);
  if (dVar3 < (double)FLOAT_803e721c) {
    iVar1 = (int)(FLOAT_803e7220 * FLOAT_803db414 +
                 (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) -
                        DOUBLE_803e7228));
    if (0xff < iVar1) {
      iVar1 = 0xff;
    }
    *(char *)(param_1 + 0x36) = (char)iVar1;
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    FUN_80035f20(param_1);
    if (*(int *)(param_1 + 0xf4) == 0) {
      if (*pcVar2 == '\x01') {
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      }
      *(undefined4 *)(param_1 + 0xf4) = 1;
    }
  }
  return;
}

