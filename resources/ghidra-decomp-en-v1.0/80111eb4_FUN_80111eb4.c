// Function: FUN_80111eb4
// Entry: 80111eb4
// Size: 256 bytes

void FUN_80111eb4(int param_1,int param_2)

{
  char cVar2;
  undefined4 uVar1;
  short sStack26;
  undefined4 local_18;
  undefined4 local_14;
  undefined2 local_10;
  
  local_18 = DAT_802c2190;
  local_14 = DAT_802c2194;
  local_10 = DAT_802c2198;
  if ((*(char *)(param_2 + 0x407) != *(char *)(param_2 + 0x409)) &&
     (*(char *)(param_1 + 0x36) != '\0')) {
    if (*(int *)(param_1 + 200) != 0) {
      FUN_8002cbc4();
      *(undefined4 *)(param_1 + 200) = 0;
    }
    cVar2 = FUN_8002e04c();
    if (cVar2 == '\0') {
      *(undefined *)(param_2 + 0x409) = 0;
    }
    else {
      if (0 < *(char *)(param_2 + 0x407)) {
        uVar1 = FUN_8002bdf4(0x18,(int)(&sStack26)[*(char *)(param_2 + 0x407)]);
        uVar1 = FUN_8002df90(uVar1,4,0xffffffff,0xffffffff,*(undefined4 *)(param_1 + 0x30));
        *(undefined4 *)(param_1 + 200) = uVar1;
        *(ushort *)(*(int *)(param_1 + 200) + 0xb0) = *(ushort *)(param_1 + 0xb0) & 7;
      }
      *(undefined *)(param_2 + 0x409) = *(undefined *)(param_2 + 0x407);
    }
  }
  return;
}

