// Function: FUN_801afc90
// Entry: 801afc90
// Size: 364 bytes

void FUN_801afc90(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  char cVar1;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar2;
  
  cVar1 = *(char *)(param_9 + 0xac);
  if (cVar1 == 'G') {
    uVar2 = FUN_80088afc(&DAT_80324668,&DAT_80324630,&DAT_803246a0,&DAT_803246d8);
    if (*(int *)(param_9 + 0xf4) == 2) {
      FUN_80088a84(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3f);
    }
    else {
      FUN_80088a84(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1f);
    }
    FUN_8000a538((int *)0xc2,0);
    FUN_8000a538((int *)0xce,0);
    FUN_8000a538((int *)0xcc,0);
    FUN_8000a538((int *)0xdb,0);
    FUN_8000a538((int *)0xf2,0);
  }
  else if (cVar1 < 'G') {
    if (cVar1 == 'E') {
      uVar2 = FUN_80088f20(7,'\0');
      uVar2 = FUN_80088a84(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
      uVar2 = FUN_80008cbc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x13e,0
                           ,in_r7,in_r8,in_r9,in_r10);
      uVar2 = FUN_80008cbc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x140,0
                           ,in_r7,in_r8,in_r9,in_r10);
      FUN_80008cbc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x13f,0,in_r7,
                   in_r8,in_r9,in_r10);
      FUN_8000a538((int *)0xda,1);
    }
    else if ('D' < cVar1) {
      FUN_8000a538((int *)0xe1,0);
      FUN_8000a538((int *)0x96,1);
    }
  }
  else if (cVar1 == 'I') {
    FUN_8000a538((int *)0x36,1);
  }
  else if (cVar1 < 'I') {
    FUN_8000a538((int *)0xc8,0);
  }
  return;
}

