// Function: FUN_80029368
// Entry: 80029368
// Size: 380 bytes

void FUN_80029368(char **param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  char *local_18;
  undefined4 local_14 [2];
  
  if ((*(ushort *)(param_1 + 6) & 0x40) != 0) {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xffbf;
    iVar2 = 0;
    for (iVar3 = 0; iVar3 < (int)(uint)(byte)(*param_1)[0xf8]; iVar3 = iVar3 + 1) {
      FUN_80053380(param_1[0xd] + iVar2);
      iVar2 = iVar2 + 0xc;
    }
  }
  pcVar4 = *param_1;
  if (param_1[0x16] != (char *)0x0) {
    FUN_80023800();
  }
  cVar1 = *pcVar4;
  *pcVar4 = cVar1 + -1;
  if ((char)(cVar1 + -1) == '\0') {
    FUN_80013c78(DAT_803dcb54,*(undefined2 *)(pcVar4 + 4));
    iVar2 = 0;
    for (iVar3 = 0; iVar3 < (int)(uint)(byte)pcVar4[0xf2]; iVar3 = iVar3 + 1) {
      FUN_800536c0(*(undefined4 *)(*(int *)(pcVar4 + 0x20) + iVar2));
      FUN_80054308();
      iVar2 = iVar2 + 4;
    }
    if ((*(int *)(pcVar4 + 100) != 0) && (*(short *)(pcVar4 + 0xec) != 0)) {
      iVar2 = 0;
      for (iVar3 = 0; iVar3 < (int)(uint)*(ushort *)(pcVar4 + 0xec); iVar3 = iVar3 + 1) {
        local_18 = *(char **)(*(int *)(pcVar4 + 100) + iVar2);
        if ((local_18 != (char *)0x0) &&
           (cVar1 = *local_18, *local_18 = cVar1 + -1, (char)(cVar1 + -1) < '\x01')) {
          FUN_80013b7c(DAT_803dcb50,&local_18,local_14);
          FUN_80013c78(DAT_803dcb50,local_14[0]);
          FUN_80023800(local_18);
        }
        iVar2 = iVar2 + 4;
      }
    }
    FUN_80023800(pcVar4);
  }
  return;
}

