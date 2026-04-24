// Function: FUN_80100fa0
// Entry: 80100fa0
// Size: 276 bytes

void FUN_80100fa0(void)

{
  undefined4 uVar1;
  
  if (DAT_803dd4bc == 0) {
    uVar1 = FUN_8002bdf4(0x18,0x1fe);
    DAT_803dd4bc = FUN_8002df90(uVar1,4,0xffffffff,0xffffffff,0);
    uVar1 = FUN_8002b588();
    FUN_8002853c(uVar1,FUN_80100dcc);
    *(undefined *)(DAT_803dd4bc + 0xad) = 1;
    uVar1 = FUN_8002b588(DAT_803dd4bc);
    FUN_8002853c(uVar1,FUN_80100c90);
    *(undefined *)(DAT_803dd4bc + 0xad) = 2;
    uVar1 = FUN_8002b588(DAT_803dd4bc);
    FUN_8002853c(uVar1,FUN_80100c90);
    FUN_8001efe0(1,0x32,0x3c,0x28);
    DAT_803dd4c4 = FUN_8001f4c8(0,1);
    if (DAT_803dd4c4 != 0) {
      FUN_8001db2c(DAT_803dd4c4,4);
      FUN_8001db3c(DAT_803dd4c4,1);
      FUN_8001db34(DAT_803dd4c4,1);
      FUN_8001dc90((double)FLOAT_803e162c,(double)FLOAT_803e1630,(double)FLOAT_803e1640,DAT_803dd4c4
                  );
      FUN_8001daf0(DAT_803dd4c4,0xb4,200,0xff,0xff);
    }
  }
  return;
}

