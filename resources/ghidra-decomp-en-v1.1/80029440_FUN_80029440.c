// Function: FUN_80029440
// Entry: 80029440
// Size: 380 bytes

void FUN_80029440(int *param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  char *local_18;
  int local_14 [2];
  
  if ((*(ushort *)(param_1 + 6) & 0x40) != 0) {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xffbf;
    iVar2 = 0;
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(*param_1 + 0xf8); iVar3 = iVar3 + 1) {
      FUN_800534fc((int *)(param_1[0xd] + iVar2));
      iVar2 = iVar2 + 0xc;
    }
  }
  pcVar4 = (char *)*param_1;
  if (param_1[0x16] != 0) {
    FUN_800238c4(param_1[0x16]);
  }
  cVar1 = *pcVar4;
  *pcVar4 = cVar1 + -1;
  if ((char)(cVar1 + -1) == '\0') {
    FUN_80013c98(DAT_803dd7d4,(uint)*(ushort *)(pcVar4 + 4));
    iVar2 = 0;
    for (iVar3 = 0; iVar3 < (int)(uint)(byte)pcVar4[0xf2]; iVar3 = iVar3 + 1) {
      FUN_8005383c(*(uint *)(*(int *)(pcVar4 + 0x20) + iVar2));
      FUN_80054484();
      iVar2 = iVar2 + 4;
    }
    if ((*(int *)(pcVar4 + 100) != 0) && (*(short *)(pcVar4 + 0xec) != 0)) {
      iVar2 = 0;
      for (iVar3 = 0; iVar3 < (int)(uint)*(ushort *)(pcVar4 + 0xec); iVar3 = iVar3 + 1) {
        local_18 = *(char **)(*(int *)(pcVar4 + 100) + iVar2);
        if ((local_18 != (char *)0x0) &&
           (cVar1 = *local_18, *local_18 = cVar1 + -1, (char)(cVar1 + -1) < '\x01')) {
          FUN_80013b9c(DAT_803dd7d0,(int)&local_18,local_14);
          FUN_80013c98(DAT_803dd7d0,local_14[0]);
          FUN_800238c4((uint)local_18);
        }
        iVar2 = iVar2 + 4;
      }
    }
    FUN_800238c4((uint)pcVar4);
  }
  return;
}

