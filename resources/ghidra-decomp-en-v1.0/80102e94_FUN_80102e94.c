// Function: FUN_80102e94
// Entry: 80102e94
// Size: 116 bytes

int FUN_80102e94(int param_1)

{
  int iVar1;
  
  if (param_1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_80023cc8(0x10,0xf,0);
    if (iVar1 != 0) {
      FUN_8001f71c(iVar1,0xb,(param_1 + -1) * 0x10,0x10);
    }
  }
  return iVar1;
}

