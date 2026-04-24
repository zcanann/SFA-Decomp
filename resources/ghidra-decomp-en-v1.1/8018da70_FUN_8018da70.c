// Function: FUN_8018da70
// Entry: 8018da70
// Size: 144 bytes

void FUN_8018da70(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  FUN_8002fb40((double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x1b)) -
                               DOUBLE_803e4a50) / FLOAT_803e4a4c),(double)FLOAT_803dc074);
  uVar1 = (uint)*(short *)(iVar2 + 0x20);
  if (uVar1 != 0xffffffff) {
    uVar1 = FUN_80020078(uVar1);
    if (uVar1 == 0) {
      *(undefined *)(param_1 + 0x36) = 0;
    }
    else {
      *(undefined *)(param_1 + 0x36) = 0xff;
    }
  }
  return;
}

