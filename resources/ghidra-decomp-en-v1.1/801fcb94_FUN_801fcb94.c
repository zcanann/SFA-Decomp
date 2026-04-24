// Function: FUN_801fcb94
// Entry: 801fcb94
// Size: 168 bytes

void FUN_801fcb94(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  uint uVar1;
  short *psVar2;
  
  if (*(short *)(param_9 + 0x46) == 999) {
    psVar2 = *(short **)(param_9 + 0xb8);
    if ((-1 < *(char *)(psVar2 + 1)) && (uVar1 = FUN_80020078((int)*psVar2), uVar1 != 0)) {
      FUN_8000bb38(0,0x109);
      FUN_8000bb38(param_9,0x10d);
      FUN_8000bb38(param_9,0x494);
      FUN_8002b95c(param_9,1);
      *(byte *)(psVar2 + 1) = *(byte *)(psVar2 + 1) & 0x7f | 0x80;
    }
  }
  else {
    FUN_801fc9b0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

