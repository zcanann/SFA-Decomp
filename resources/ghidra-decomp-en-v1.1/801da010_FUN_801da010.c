// Function: FUN_801da010
// Entry: 801da010
// Size: 244 bytes

/* WARNING: Removing unreachable block (ram,0x801da09c) */

void FUN_801da010(undefined2 *param_1,int param_2)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  uint *puVar5;
  
  pbVar4 = *(byte **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined4 *)(param_1 + 0x7a) = 0;
  iVar3 = 0;
  puVar5 = (uint *)&DAT_803dccc0;
  do {
    uVar2 = FUN_80020078(*puVar5);
    if (uVar2 != 0) {
      *pbVar4 = (char)iVar3 + 1;
    }
    puVar5 = puVar5 + 1;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 2);
  bVar1 = *pbVar4;
  if (bVar1 == 1) {
    FUN_8002b7b0((int)param_1,0,0,0,'\0','\x04');
  }
  else if ((bVar1 == 0) || (bVar1 < 3)) {
    FUN_8002b7b0((int)param_1,0,0,0,'\0','\x03');
  }
  return;
}

