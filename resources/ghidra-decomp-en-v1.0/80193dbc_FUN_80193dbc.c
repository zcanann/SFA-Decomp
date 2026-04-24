// Function: FUN_80193dbc
// Entry: 80193dbc
// Size: 364 bytes

void FUN_80193dbc(undefined4 param_1,undefined4 param_2,char *param_3,int param_4)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar1 = FUN_802860dc();
  if ((*(byte *)(param_4 + 0x1c) & 0x10) == 0) {
    for (iVar5 = 0; iVar5 < (int)(uint)*(ushort *)(iVar1 + 0x9a); iVar5 = iVar5 + 1) {
      iVar3 = FUN_800606ec(iVar1,iVar5);
      uVar2 = FUN_80060678();
      if (*(byte *)(param_4 + 0x1b) == uVar2) {
        if (*param_3 == '\0') {
          *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) | 2;
          if ((*(byte *)(param_4 + 0x1c) & 2) != 0) {
            *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) | 1;
          }
        }
        else {
          *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) & 0xfffffffd;
          if ((*(byte *)(param_4 + 0x1c) & 2) != 0) {
            *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) & 0xfffffffe;
          }
        }
      }
    }
  }
  if ((*(byte *)(param_4 + 0x1c) & 2) != 0) {
    for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(iVar1 + 0xa2); iVar5 = iVar5 + 1) {
      iVar3 = FUN_8006070c(iVar1,iVar5);
      iVar4 = FUN_8004c250(iVar3,0);
      if (*(char *)(param_4 + 0x1b) == *(char *)(iVar4 + 5)) {
        if (*param_3 == '\0') {
          *(uint *)(iVar3 + 0x3c) = *(uint *)(iVar3 + 0x3c) | 2;
        }
        else {
          *(uint *)(iVar3 + 0x3c) = *(uint *)(iVar3 + 0x3c) & 0xfffffffd;
        }
      }
    }
  }
  FUN_80286128();
  return;
}

