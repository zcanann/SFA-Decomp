// Function: FUN_8025203c
// Entry: 8025203c
// Size: 152 bytes

bool FUN_8025203c(int param_1)

{
  uint uVar1;
  uint uVar2;
  
  FUN_8024377c();
  uVar1 = read_volatile_4(DAT_cc006434);
  if (param_1 == 0) {
    uVar2 = uVar1 & 0xf7ffffff;
  }
  else {
    DAT_803ae3e0 = 0;
    uVar2 = uVar1 | 0x8000000;
    DAT_803ae3e4 = 0;
    DAT_803ae3e8 = 0;
    DAT_803ae3ec = 0;
  }
  write_volatile_4(DAT_cc006434,uVar2 & 0x7ffffffe);
  FUN_802437a4();
  return (uVar1 & 0x8000000) != 0;
}

