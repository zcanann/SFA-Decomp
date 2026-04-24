// Function: FUN_801af6dc
// Entry: 801af6dc
// Size: 364 bytes

void FUN_801af6dc(int param_1)

{
  char cVar1;
  
  cVar1 = *(char *)(param_1 + 0xac);
  if (cVar1 == 'G') {
    FUN_80088870(&DAT_80323a28,&DAT_803239f0,&DAT_80323a60,&DAT_80323a98);
    if (*(int *)(param_1 + 0xf4) == 2) {
      FUN_800887f8(0x3f);
    }
    else {
      FUN_800887f8(0x1f);
    }
    FUN_8000a518(0xc2,0);
    FUN_8000a518(0xce,0);
    FUN_8000a518(0xcc,0);
    FUN_8000a518(0xdb,0);
    FUN_8000a518(0xf2,0);
  }
  else if (cVar1 < 'G') {
    if (cVar1 == 'E') {
      FUN_80088c94(7,0);
      FUN_800887f8(0);
      FUN_80008cbc(0,0,0x13e,0);
      FUN_80008cbc(0,0,0x140,0);
      FUN_80008cbc(0,0,0x13f,0);
      FUN_8000a518(0xda,1);
    }
    else if ('D' < cVar1) {
      FUN_8000a518(0xe1,0);
      FUN_8000a518(0x96,1);
    }
  }
  else if (cVar1 == 'I') {
    FUN_8000a518(0x36,1);
  }
  else if (cVar1 < 'I') {
    FUN_8000a518(200,0);
  }
  return;
}

