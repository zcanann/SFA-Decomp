// Function: FUN_80080384
// Entry: 80080384
// Size: 104 bytes

void FUN_80080384(void)

{
  FUN_8000cfa0();
  FUN_8000cf54(0);
  if (DAT_803db71c == -1) {
    if (DAT_803db718 != -1) {
      FUN_8001b700();
      FUN_8001bb78(DAT_803db718);
      DAT_803db718 = -1;
    }
  }
  else {
    FUN_8001bbd8();
    DAT_803db71c = -1;
    DAT_803db714 = 0xffffffff;
  }
  return;
}

