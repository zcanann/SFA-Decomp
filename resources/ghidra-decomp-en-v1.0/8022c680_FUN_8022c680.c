// Function: FUN_8022c680
// Entry: 8022c680
// Size: 292 bytes

void FUN_8022c680(int param_1)

{
  char cVar1;
  int iVar2;
  
  cVar1 = *(char *)(param_1 + 0xac);
  if (cVar1 == '<') {
    FUN_800552e8(99,0);
  }
  else if (cVar1 < '<') {
    if (cVar1 == ':') {
      iVar2 = FUN_8001ffb4(0xc85);
      if (iVar2 == 0) {
        FUN_800552e8(0x6c,0);
      }
      else {
        FUN_800200e8(0x405,0);
        (**(code **)(*DAT_803dcaac + 0x44))(0xb,5);
        (**(code **)(*DAT_803dcaac + 0x50))(0xb,10,1);
        (**(code **)(*DAT_803dcaac + 0x50))(0xb,0xb,1);
        FUN_800552e8(0x22,0);
      }
    }
    else if ('9' < cVar1) {
      FUN_800552e8(0x77,0);
    }
  }
  else if (cVar1 == '>') {
    FUN_800552e8(0x79,0);
  }
  else if (cVar1 < '>') {
    FUN_800552e8(0x78,0);
  }
  return;
}

