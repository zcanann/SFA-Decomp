// Function: FUN_801f654c
// Entry: 801f654c
// Size: 516 bytes

void FUN_801f654c(int param_1)

{
  char cVar1;
  short sVar2;
  char cVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  sVar2 = *(short *)(iVar4 + 8);
  if (sVar2 == 0x21) {
    FUN_800200e8(0xd1b,1);
  }
  else if (sVar2 == 1) {
    cVar3 = FUN_80088e08(0);
    cVar1 = *(char *)(iVar4 + 0xf);
    if ((cVar1 == '\0') || (cVar3 != '\0')) {
      if ((cVar1 == '\0') && (cVar3 != '\0')) {
        FUN_80008b74(0,0,0x217,0);
        FUN_80008b74(param_1,param_1,0x216,0);
        FUN_80008b74(param_1,param_1,0x84,0);
        FUN_80008b74(param_1,param_1,0x8a,0);
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),4,0);
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),10,1);
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0xb,1);
      }
    }
    else {
      FUN_80008b74(0,0,0x22d,0);
      FUN_80008b74(param_1,param_1,0x22c,0);
      FUN_80008b74(param_1,param_1,0x229,0);
      FUN_80008b74(param_1,param_1,0x22a,0);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),4,1);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),10,0);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0xb,0);
    }
  }
  return;
}

