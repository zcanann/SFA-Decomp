// Function: FUN_8027b06c
// Entry: 8027b06c
// Size: 496 bytes

void FUN_8027b06c(int param_1,uint param_2)

{
  int iVar1;
  uint uVar2;
  
  uVar2 = *(uint *)(param_1 + 4);
  if (uVar2 != param_2) {
    if (uVar2 < param_2) {
      if (*(char *)(param_1 + 2) == '\x05') {
        *(uint *)(param_1 + 0x14) = (uint)((ulonglong)uVar2 * 0x124924925 >> 0x21) & 0xfffffff8;
        *(uint *)(param_1 + 0x18) = param_2 - *(int *)(param_1 + 4);
        *(undefined4 *)(param_1 + 0x1c) = 0;
        *(undefined4 *)(param_1 + 0x20) = 0;
        iVar1 = (*DAT_803cbbdc)(1,param_1 + 0x10);
        if (iVar1 != 0) {
          uVar2 = *(int *)(param_1 + 4) + iVar1;
          *(uint *)(param_1 + 4) = uVar2 - (uVar2 / DAT_803cb294) * DAT_803cb294;
        }
      }
    }
    else if (param_2 == 0) {
      if (*(char *)(param_1 + 2) == '\x05') {
        *(uint *)(param_1 + 0x14) = (uint)((ulonglong)uVar2 * 0x124924925 >> 0x21) & 0xfffffff8;
        *(uint *)(param_1 + 0x18) = DAT_803cb294 - *(int *)(param_1 + 4);
        *(undefined4 *)(param_1 + 0x1c) = 0;
        *(undefined4 *)(param_1 + 0x20) = 0;
        iVar1 = (*DAT_803cbbdc)(1,param_1 + 0x10);
        if (iVar1 != 0) {
          uVar2 = *(int *)(param_1 + 4) + iVar1;
          *(uint *)(param_1 + 4) = uVar2 - (uVar2 / DAT_803cb294) * DAT_803cb294;
        }
      }
    }
    else if (*(char *)(param_1 + 2) == '\x05') {
      *(uint *)(param_1 + 0x14) = (uint)((ulonglong)uVar2 * 0x124924925 >> 0x21) & 0xfffffff8;
      *(uint *)(param_1 + 0x18) = DAT_803cb294 - *(int *)(param_1 + 4);
      *(undefined4 *)(param_1 + 0x1c) = 0;
      *(uint *)(param_1 + 0x20) = param_2;
      iVar1 = (*DAT_803cbbdc)(1,param_1 + 0x10);
      if (iVar1 != 0) {
        uVar2 = *(int *)(param_1 + 4) + iVar1;
        *(uint *)(param_1 + 4) = uVar2 - (uVar2 / DAT_803cb294) * DAT_803cb294;
      }
    }
  }
  return;
}

