// Function: FUN_80020c2c
// Entry: 80020c2c
// Size: 352 bytes

void FUN_80020c2c(void)

{
  int iVar1;
  int *piVar2;
  
  FUN_8004a868();
  if (DAT_803dca3d == '\x01') {
    FUN_80014f40();
    FUN_80013434();
    FUN_80020958();
    FUN_8000e380();
    FUN_8001f67c();
    FUN_800481d4();
    FUN_80009bd0();
    FUN_8000d734();
  }
  FUN_801375c8(0);
  (**(code **)(*DAT_803dca4c + 4))(0,0,0);
  if (DAT_803dca3d == '\x01') {
    if (DAT_803dca48 != 0) {
      if (DAT_803dca46 == 0) {
        FUN_80076510((double)FLOAT_803de7b0,(double)FLOAT_803de7b0,0x280,0x1e0);
        piVar2 = (int *)&DAT_803dcae8;
        for (iVar1 = 0; iVar1 < (int)(uint)DAT_803dca48; iVar1 = iVar1 + 1) {
          FUN_8003b8f4((double)FLOAT_803de7a8,*piVar2,0,0,0,0);
          if ((*(short *)(*piVar2 + 0x46) == 0x882) || (*(short *)(*piVar2 + 0x46) == 0x887)) {
            FUN_800414b4();
          }
          piVar2 = piVar2 + 1;
        }
        FUN_8001476c(0,0,0,0);
      }
      FUN_80015624();
      FUN_80019c24();
    }
    FUN_8001b46c(0);
    FUN_80014f3c();
    FUN_8001b444(0);
  }
  FUN_8004a43c(1,1);
  FUN_8002e3fc();
  FUN_800234ec(1);
  FUN_800207f4();
  return;
}

