// Function: FUN_8028f380
// Entry: 8028f380
// Size: 312 bytes

undefined4 FUN_8028f380(undefined4 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  if (param_1 == (undefined4 *)0x0) {
    uVar1 = FUN_8028e23c();
  }
  else if ((*(char *)((int)param_1 + 10) == '\0') && ((*(ushort *)(param_1 + 1) >> 6 & 7) != 0)) {
    if ((*(byte *)(param_1 + 1) >> 3 & 7) == 1) {
      uVar1 = 0;
    }
    else {
      if (2 < *(byte *)(param_1 + 2) >> 5) {
        *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) & 0x1f | 0x40;
      }
      if (*(byte *)(param_1 + 2) >> 5 == 2) {
        param_1[10] = 0;
      }
      if (*(byte *)(param_1 + 2) >> 5 == 1) {
        if ((*(ushort *)(param_1 + 1) >> 6 & 7) == 1) {
          iVar3 = FUN_8028f7d4((int)param_1);
        }
        else {
          iVar3 = 0;
        }
        iVar2 = FUN_8028ef5c(param_1,(undefined4 *)0x0);
        if (iVar2 == 0) {
          uVar1 = 0;
          *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) & 0x1f;
          param_1[6] = iVar3;
          param_1[10] = 0;
        }
        else {
          *(undefined *)((int)param_1 + 10) = 1;
          uVar1 = 0xffffffff;
          param_1[10] = 0;
        }
      }
      else {
        uVar1 = 0;
        *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) & 0x1f;
      }
    }
  }
  else {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}

