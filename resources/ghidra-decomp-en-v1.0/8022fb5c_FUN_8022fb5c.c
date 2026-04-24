// Function: FUN_8022fb5c
// Entry: 8022fb5c
// Size: 380 bytes

void FUN_8022fb5c(int param_1,char *param_2,int param_3)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  cVar1 = *param_2;
  if (cVar1 == '\0') {
    FUN_8000bb18(param_3,0x2a9);
    if (*(short *)(param_3 + 0x46) == 0x601) {
      FUN_8022d64c(param_3,1);
      FUN_8022d520(param_3,10);
    }
  }
  else if (cVar1 == '\x01') {
    FUN_8000bb18(param_3,0x2a9);
    if (*(short *)(param_3 + 0x46) == 0x601) {
      FUN_8022d634(param_3,1);
      uVar2 = FUN_8022d580(param_3);
      FUN_8022d64c(param_3,uVar2);
    }
  }
  else if ((cVar1 == '\x03') || (cVar1 == '\x04')) {
    FUN_8000bb18(param_3,0x2a9);
    FUN_8001ff3c((int)*(short *)(iVar4 + 0x1e));
  }
  else {
    FUN_8000bb18(param_3,0x2ab);
    if (*(short *)(param_3 + 0x46) == 0x601) {
      FUN_8022d5f0(param_3);
      FUN_8022d64c(param_3,1);
      FUN_8022d520(param_3,0x14);
      iVar4 = FUN_8022d508(param_3);
      iVar3 = FUN_8022d514(param_3);
      if (iVar3 == iVar4) {
        if (((byte)param_2[0x14] >> 5 & 1) != 0) {
          FUN_80125ba4(7);
        }
      }
      else if (((byte)param_2[0x14] >> 5 & 1) != 0) {
        FUN_80125ba4(9);
      }
    }
  }
  param_2[0x15] = '\x02';
  return;
}

