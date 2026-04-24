// Function: FUN_801b0c24
// Entry: 801b0c24
// Size: 276 bytes

undefined4 FUN_801b0c24(uint param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar2 + 0x1a) == '\x01') {
    FUN_8000bb38(param_1,0x72);
  }
  else {
    FUN_8000b7dc(param_1,0x40);
  }
  bVar1 = *(byte *)(param_3 + 0x80);
  if (bVar1 == 2) {
    FUN_800201ac(0x2e,1);
  }
  else if (bVar1 < 2) {
    if (bVar1 != 0) {
      *(byte *)(iVar2 + 0x1b) = *(byte *)(iVar2 + 0x1b) ^ 1;
    }
  }
  else if (bVar1 < 4) {
    *(undefined *)(iVar2 + 0x1a) = 4;
  }
  if (*(char *)(iVar2 + 0x1b) == '\0') {
    FUN_8000b7dc(param_1,1);
  }
  else {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0xd7,0,0,0xffffffff,0);
    FUN_8000b7dc(param_1,5);
  }
  *(undefined *)(param_3 + 0x80) = 0;
  return 0;
}

