// Function: FUN_801f27e4
// Entry: 801f27e4
// Size: 400 bytes

void FUN_801f27e4(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0xa0) != 2) {
    FUN_80030334((double)FLOAT_803e5d98,param_1,2,0);
  }
  FUN_8002fa48((double)FLOAT_803e5d9c,
               (double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) - DOUBLE_803e5da0),
               param_1,0);
  *(undefined *)(iVar2 + 0x24) = 1;
  if (*(char *)(iVar2 + 0x24) == '\0') {
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      FUN_800200e8(0xd0,1);
      *(undefined *)(iVar2 + 0x24) = 1;
      FUN_80014b3c(0,0x100);
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      FUN_8002b9ec();
      iVar1 = FUN_80296a14();
      if (iVar1 < 1) {
        iVar1 = FUN_8001ffb4(0xb1);
        if (((iVar1 == 0) || (iVar1 = FUN_8001ffb4(0xb2), iVar1 == 0)) ||
           (iVar1 = FUN_8001ffb4(0xb3), iVar1 == 0)) {
          *(undefined *)(iVar2 + 0x25) = 1;
          (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
          FUN_80014b3c(0,0x100);
        }
      }
      else {
        *(undefined *)(iVar2 + 0x25) = 2;
        (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
        FUN_80014b3c(0,0x100);
      }
    }
  }
  return;
}

