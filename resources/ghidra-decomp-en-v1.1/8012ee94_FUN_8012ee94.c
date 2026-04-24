// Function: FUN_8012ee94
// Entry: 8012ee94
// Size: 172 bytes

void FUN_8012ee94(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  if ((param_1 != -1) && (DAT_803dc6d8 == -1)) {
    FUN_80017400(0x7c);
    DAT_803de428 = 1;
    DAT_803de550 = 0;
    DAT_803dc6d8 = (short)param_1;
    DAT_803de54a = 0xffff;
    DAT_803de548 = 1;
    FUN_80016c80((undefined4 *)&DAT_803aa0a0);
    if (param_4 == 0) {
      DAT_803de429 = 0;
    }
    else {
      FUN_800207ac(1);
      FUN_800206ec(0xff);
      DAT_803de429 = 1;
    }
  }
  return;
}

