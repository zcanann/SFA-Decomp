// Function: FUN_8018d4f4
// Entry: 8018d4f4
// Size: 144 bytes

void FUN_8018d4f4(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x4c);
  FUN_8002fa48((double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar1 + 0x1b)) -
                               DOUBLE_803e3db8) / FLOAT_803e3db4),(double)FLOAT_803db414,param_1,0);
  if (*(short *)(iVar1 + 0x20) != -1) {
    iVar1 = FUN_8001ffb4();
    if (iVar1 == 0) {
      *(undefined *)(param_1 + 0x36) = 0;
    }
    else {
      *(undefined *)(param_1 + 0x36) = 0xff;
    }
  }
  return;
}

