// Function: FUN_80282594
// Entry: 80282594
// Size: 156 bytes

void FUN_80282594(int param_1,uint param_2,undefined4 param_3,byte param_4,int param_5)

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
      param_2 = FUN_80283418(param_2);
    }
    else {
      param_4 = param_4 | 0x10;
    }
    iVar2 = (uint)bVar1 * 8;
    *(char *)(param_1 + iVar2) = (char)param_2;
    iVar2 = param_1 + iVar2;
    *(byte *)(iVar2 + 1) = param_4;
    *(undefined4 *)(iVar2 + 4) = param_3;
  }
  return;
}

