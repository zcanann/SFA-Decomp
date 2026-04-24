// Function: FUN_801d9a20
// Entry: 801d9a20
// Size: 244 bytes

/* WARNING: Removing unreachable block (ram,0x801d9aac) */

void FUN_801d9a20(undefined2 *param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  undefined4 *puVar5;
  
  pbVar4 = *(byte **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined4 *)(param_1 + 0x7a) = 0;
  iVar3 = 0;
  puVar5 = (undefined4 *)&DAT_803dc058;
  do {
    iVar2 = FUN_8001ffb4(*puVar5);
    if (iVar2 != 0) {
      *pbVar4 = (char)iVar3 + 1;
    }
    puVar5 = puVar5 + 1;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 2);
  bVar1 = *pbVar4;
  if (bVar1 == 1) {
    FUN_8002b6d8(param_1,0,0,0,0,4);
  }
  else if ((bVar1 == 0) || (bVar1 < 3)) {
    FUN_8002b6d8(param_1,0,0,0,0,3);
  }
  return;
}

