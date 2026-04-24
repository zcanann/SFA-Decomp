// Function: FUN_80275058
// Entry: 80275058
// Size: 96 bytes

undefined4 FUN_80275058(undefined2 param_1)

{
  undefined4 uVar1;
  
  uRam803de2b4 = param_1;
  DAT_803de2b8 = (undefined4 *)
                 FUN_80282ee8(&DAT_803de2b0,&DAT_803c0278,DAT_803de28a,8,&LAB_80275048);
  if (DAT_803de2b8 == (undefined4 *)0x0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *DAT_803de2b8;
  }
  return uVar1;
}

