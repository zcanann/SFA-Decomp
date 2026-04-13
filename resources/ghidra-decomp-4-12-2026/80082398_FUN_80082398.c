// Function: FUN_80082398
// Entry: 80082398
// Size: 320 bytes

void FUN_80082398(int param_1)

{
  int iVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  
  *(undefined2 *)(param_1 + 0xc2) = 0;
  *(undefined2 *)(param_1 + 0xc4) = 0;
  *(undefined2 *)(param_1 + 0xc6) = 0;
  *(undefined2 *)(param_1 + 200) = 0;
  *(undefined2 *)(param_1 + 0xca) = 0;
  *(undefined2 *)(param_1 + 0xcc) = 0;
  *(undefined2 *)(param_1 + 0xce) = 0;
  *(undefined2 *)(param_1 + 0xd0) = 0;
  *(undefined2 *)(param_1 + 0xd2) = 0;
  *(undefined2 *)(param_1 + 0xd4) = 0;
  *(undefined2 *)(param_1 + 0xd6) = 0;
  *(undefined2 *)(param_1 + 0xd8) = 0;
  *(undefined2 *)(param_1 + 0xda) = 0;
  *(undefined2 *)(param_1 + 0xdc) = 0;
  *(undefined2 *)(param_1 + 0xde) = 0;
  *(undefined2 *)(param_1 + 0xe0) = 0;
  *(undefined2 *)(param_1 + 0xe2) = 0;
  *(undefined2 *)(param_1 + 0xe4) = 0;
  iVar3 = param_1 + 0x24;
  iVar1 = 1;
  do {
    *(undefined2 *)(iVar3 + 0xc2) = 0;
    iVar3 = iVar3 + 2;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  uVar5 = 0;
  iVar1 = param_1;
  for (iVar3 = 0; iVar3 < *(short *)(param_1 + 100); iVar3 = iVar3 + iVar4) {
    iVar4 = 0;
    while ((iVar3 + iVar4 < (int)*(short *)(param_1 + 100) &&
           (uVar5 == ((int)*(char *)(*(int *)(param_1 + 0x98) + (iVar3 + iVar4) * 8 + 5) & 0x1fU))))
    {
      iVar4 = iVar4 + 1;
    }
    *(short *)(iVar1 + 0xc2) = (short)iVar4;
    *(short *)(iVar1 + 0x9c) = (short)iVar3;
    iVar1 = iVar1 + 2;
    uVar5 = uVar5 + 1;
  }
  *(undefined2 *)(param_1 + 0x5c) = 1000;
  iVar3 = 0;
  iVar1 = 0;
  while( true ) {
    if (1 < iVar3) {
      return;
    }
    if (*(short *)(param_1 + 0x62) <= iVar3) break;
    pcVar2 = (char *)(*(int *)(param_1 + 0x94) + iVar1);
    if (*pcVar2 == -1) {
      *(short *)(param_1 + 0x5c) = *(short *)(pcVar2 + 2) + 1;
    }
    iVar1 = iVar1 + 4;
    iVar3 = iVar3 + 1;
  }
  return;
}

