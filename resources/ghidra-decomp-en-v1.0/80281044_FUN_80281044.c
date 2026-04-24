// Function: FUN_80281044
// Entry: 80281044
// Size: 284 bytes

int FUN_80281044(byte param_1,undefined param_2,undefined param_3,byte param_4,undefined4 param_5,
                undefined4 param_6)

{
  byte bVar1;
  int iVar2;
  undefined4 local_18 [3];
  
  DAT_803de238 = 0;
  DAT_803bd360 = param_1;
  if (0x40 < param_1) {
    DAT_803bd360 = 0x40;
  }
  DAT_803bd363 = param_4;
  if (8 < param_4) {
    DAT_803bd363 = 8;
  }
  local_18[0] = 32000;
  DAT_803bd361 = param_2;
  DAT_803bd362 = param_3;
  iVar2 = FUN_8028314c(local_18,DAT_803bd360,DAT_803bd363,param_5);
  bVar1 = DAT_803bd360;
  if (iVar2 == 0) {
    FUN_8027b420();
    FUN_80275260(0,param_6);
    FUN_8026f30c();
    DAT_803de270 = 0;
    FUN_802720a8(32000,bVar1);
    FUN_80272ea4();
    FUN_8027acb8();
    FUN_80280ffc(param_5);
    DAT_803de238 = 1;
    iVar2 = 0;
  }
  return iVar2;
}

