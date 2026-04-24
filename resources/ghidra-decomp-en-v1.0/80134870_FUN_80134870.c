// Function: FUN_80134870
// Entry: 80134870
// Size: 344 bytes

void FUN_80134870(int param_1,int param_2)

{
  char cVar1;
  short sVar2;
  int iVar3;
  
  for (iVar3 = 0; iVar3 < *(char *)(param_2 + 0x1b); iVar3 = iVar3 + 1) {
    sVar2 = *(short *)(param_1 + 0x46);
    if (sVar2 == 0x77f) {
      cVar1 = *(char *)(param_2 + iVar3 + 0x13);
      if (cVar1 == '\0') {
        FUN_8000bb18(param_1,0x36b);
      }
      else if (cVar1 == '\a') {
        FUN_8000bb18(param_1,0x421);
      }
    }
    else if (sVar2 < 0x77f) {
      if (sVar2 == 0x77d) {
        if (*(char *)(param_2 + iVar3 + 0x13) == '\0') {
          FUN_8000bb18(param_1,0x368);
        }
      }
      else if (0x77c < sVar2) {
        cVar1 = *(char *)(param_2 + iVar3 + 0x13);
        if (cVar1 == '\0') {
          FUN_8000bb18(param_1,0x370);
        }
        else if (cVar1 == '\a') {
          FUN_8000bb18(param_1,0x36c);
        }
      }
    }
    else if (sVar2 < 0x781) {
      cVar1 = *(char *)(param_2 + iVar3 + 0x13);
      if (cVar1 == '\0') {
        FUN_8000bb18(param_1,0x36a);
      }
      else if (cVar1 == '\a') {
        FUN_8000bb18(param_1,0x369);
      }
    }
  }
  return;
}

