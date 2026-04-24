// Function: FUN_801cfd68
// Entry: 801cfd68
// Size: 348 bytes

undefined4 FUN_801cfd68(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_8002e0b4(*(undefined4 *)(&DAT_803269f8 + (uint)*(byte *)(param_1 + 0xe) * 4));
  iVar2 = FUN_80037fa4(uVar1,0x1ee);
  if (iVar2 == 0) {
    if (*(byte *)(param_1 + 0xe) != 0) {
      uVar1 = FUN_8002e0b4((&PTR_LAB_803269f4)[*(byte *)(param_1 + 0xe)]);
      iVar2 = FUN_80037fa4(uVar1,0x1ee);
      if (iVar2 != 0) {
        (**(code **)(*DAT_803dca54 + 0x48))(0,uVar1,0xffffffff);
        *(undefined *)(param_1 + 4) = 9;
        *(char *)(param_1 + 0xc) =
             (char)*(undefined4 *)(&DAT_80326a10 + (uint)*(byte *)(param_1 + 0xe) * 4);
        *(undefined *)(param_1 + 5) = 0;
        return 2;
      }
    }
    uVar1 = 0;
  }
  else {
    (**(code **)(*DAT_803dca54 + 0x48))(0,uVar1,0xffffffff);
    *(undefined *)(param_1 + 4) = 9;
    *(char *)(param_1 + 0xc) =
         (char)*(undefined4 *)(&DAT_80326a14 + (uint)*(byte *)(param_1 + 0xe) * 4);
    *(char *)(param_1 + 0xd) =
         (char)*(undefined4 *)(&DAT_80326a30 + (uint)*(byte *)(param_1 + 0xe) * 4);
    *(char *)(param_1 + 0xe) = *(char *)(param_1 + 0xe) + '\x01';
    *(undefined *)(param_1 + 5) = 0x1e;
    uVar1 = 1;
  }
  return uVar1;
}

