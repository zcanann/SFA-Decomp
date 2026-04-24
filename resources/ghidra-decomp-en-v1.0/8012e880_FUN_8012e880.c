// Function: FUN_8012e880
// Entry: 8012e880
// Size: 452 bytes

void FUN_8012e880(void)

{
  uint uVar1;
  int iVar2;
  
  FUN_8002b9ec();
  if (DAT_803dd7a8 == '\0') {
    DAT_803dd8d0 = DAT_803dd8d0 + (ushort)DAT_803db410 * -8;
    if (DAT_803dd8d0 < 0) {
      DAT_803dd8d0 = 0;
    }
  }
  else {
    if (DAT_803dd8c8 != '\0') {
      (**(code **)(*DAT_803dca50 + 0x5c))(0x41,1);
    }
    DAT_803dd8d0 = 0xff;
  }
  if (DAT_803dd8d0 == 0) {
    DAT_803dba70 = 0xffff;
  }
  else if ((int)DAT_803dd8ca == 0xffffffff) {
    uVar1 = FUN_80014e70(0);
    DAT_803a944c = (int)((uVar1 & 0x100) != 0);
    if (DAT_803a9448 == 1) {
      FUN_80014b3c(0,0x100);
      DAT_803dd8a4 = DAT_803dd8a4 & 0xfffffeff;
      DAT_803dd7a8 = '\0';
      if (DAT_803dd7a9 != '\0') {
        FUN_800206e8(0);
        DAT_803dd7a9 = '\0';
      }
    }
    if (DAT_803dd7a8 != '\0') {
      FUN_80014b0c();
    }
  }
  else {
    FLOAT_803dd8cc = FLOAT_803dd8cc - FLOAT_803db414;
    if (FLOAT_803dd8cc <= FLOAT_803e1e3c) {
      FLOAT_803dd8cc =
           (float)((double)CONCAT44(0x43300000,(int)DAT_803dd8ca ^ 0x80000000) - DOUBLE_803e1e78);
      DAT_803a9444 = DAT_803a9444 + 1;
      iVar2 = FUN_80019570(DAT_803dba70);
      if ((int)(uint)*(ushort *)(iVar2 + 2) <= DAT_803a9444) {
        DAT_803a9444 = *(ushort *)(iVar2 + 2) - 1;
        DAT_803dd7a8 = '\0';
      }
    }
  }
  return;
}

