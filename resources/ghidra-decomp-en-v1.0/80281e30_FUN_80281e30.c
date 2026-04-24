// Function: FUN_80281e30
// Entry: 80281e30
// Size: 156 bytes

void FUN_80281e30(int param_1,undefined4 param_2,undefined4 param_3,byte param_4,int param_5)

{
  byte bVar1;
  int iVar2;
  
  if (param_4 == 0) {
    *(undefined *)(param_1 + 0x22) = 0;
  }
  bVar1 = *(byte *)(param_1 + 0x22);
  if (bVar1 < 4) {
    *(byte *)(param_1 + 0x22) = bVar1 + 1;
    if (param_5 == 0) {
      param_2 = FUN_80282cb4(param_2);
    }
    else {
      param_4 = param_4 | 0x10;
    }
    iVar2 = (uint)bVar1 * 8;
    *(char *)(param_1 + iVar2) = (char)param_2;
    param_1 = param_1 + iVar2;
    *(byte *)(param_1 + 1) = param_4;
    *(undefined4 *)(param_1 + 4) = param_3;
  }
  return;
}

