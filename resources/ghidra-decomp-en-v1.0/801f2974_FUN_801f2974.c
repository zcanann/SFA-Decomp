// Function: FUN_801f2974
// Entry: 801f2974
// Size: 252 bytes

undefined4 FUN_801f2974(int param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  uVar2 = FUN_8002b9ec();
  iVar4 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    cVar1 = *(char *)(iVar4 + 0x25);
    if (cVar1 == '\x01') {
      if (*(char *)(param_3 + iVar3 + 0x81) == '\x04') {
        FUN_80296a24(uVar2,5);
      }
    }
    else if (cVar1 != '\x02') {
      cVar1 = *(char *)(param_3 + iVar3 + 0x81);
      if (cVar1 == '\x01') {
        FUN_800200e8(0xd0,1);
        *(undefined *)(iVar4 + 0x24) = 1;
      }
      else if (cVar1 == '\x02') {
        FUN_80296474(uVar2,0,1);
        FUN_80296a24(uVar2,5);
      }
    }
  }
  return 0;
}

