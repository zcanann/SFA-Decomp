// Function: FUN_8028206c
// Entry: 8028206c
// Size: 296 bytes

void FUN_8028206c(byte param_1,byte param_2,byte param_3,uint param_4)

{
  byte bVar1;
  
  if (param_2 != 0xff) {
    bVar1 = (byte)param_4;
    if (param_1 < 0x40) {
      FUN_80281a9c(param_1 & 0x1f,param_2,param_3,(byte)(param_4 >> 7));
      FUN_80281a9c((param_1 & 0x1f) + 0x20,param_2,param_3,bVar1 & 0x7f);
    }
    else if ((byte)(param_1 + 0x80) < 2) {
      FUN_80281a9c(param_1 & 0xfe,param_2,param_3,(byte)(param_4 >> 7));
      FUN_80281a9c((param_1 & 0xfe) + 1,param_2,param_3,bVar1 & 0x7f);
    }
    else if ((byte)(param_1 + 0x7c) < 2) {
      FUN_80281a9c(param_1 & 0xfe,param_2,param_3,(byte)(param_4 >> 7));
      FUN_80281a9c((param_1 & 0xfe) + 1,param_2,param_3,bVar1 & 0x7f);
    }
    else {
      FUN_80281a9c(param_1,param_2,param_3,(byte)(param_4 >> 7));
    }
  }
  return;
}

