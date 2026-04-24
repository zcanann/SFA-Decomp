// Function: FUN_80175428
// Entry: 80175428
// Size: 248 bytes

void FUN_80175428(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 *local_28;
  int local_24;
  undefined4 local_20 [5];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  local_28 = (undefined4 *)0x0;
  while (iVar1 = FUN_800374ec(param_1,&local_24,local_20,&local_28), iVar1 != 0) {
    if (local_24 == 0x40001) {
      if (*(short *)(param_1 + 0x46) == 0x21e) {
        *(undefined4 *)(iVar2 + 0xf0) = *local_28;
      }
      if (*(short *)(param_1 + 0x46) == 0x411) {
        *(undefined4 *)(iVar2 + 0xf0) = *local_28;
      }
    }
    else if (local_24 < 0x40001) {
      if (((local_24 == 0xe) && (*(short *)(param_1 + 0x46) != 0x21e)) &&
         (*(short *)(param_1 + 0x46) != 0x411)) {
        FUN_8002cbc4(param_1);
      }
    }
    else if (local_24 == 0xf0003) {
      *(undefined4 *)(iVar2 + 0xb8) = local_20[0];
    }
  }
  return;
}

