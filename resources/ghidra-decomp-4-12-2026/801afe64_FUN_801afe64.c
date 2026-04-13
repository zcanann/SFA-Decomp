// Function: FUN_801afe64
// Entry: 801afe64
// Size: 196 bytes

void FUN_801afe64(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  char *pcVar2;
  double dVar3;
  double dVar4;
  
  pcVar2 = *(char **)(param_9 + 0xb8);
  iVar1 = FUN_8002bac4();
  if (iVar1 != 0) {
    if (*pcVar2 != *(char *)(param_9 + 0xac)) {
      dVar3 = (double)*(float *)(iVar1 + 0xc);
      dVar4 = (double)*(float *)(iVar1 + 0x14);
      iVar1 = FUN_8005b128();
      if (*(char *)(param_9 + 0xac) != iVar1) {
        return;
      }
      FUN_801afc90(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
    iVar1 = FUN_8005b128();
    if (*(char *)(param_9 + 0xac) == iVar1) {
      FUN_801afb1c(param_9);
    }
    iVar1 = FUN_8005b128();
    *pcVar2 = (char)iVar1;
  }
  return;
}

