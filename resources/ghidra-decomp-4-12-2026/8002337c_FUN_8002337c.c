// Function: FUN_8002337c
// Entry: 8002337c
// Size: 84 bytes

int FUN_8002337c(uint param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  
  iVar3 = 0;
  puVar2 = &DAT_80341300;
  uVar1 = (uint)DAT_803dd7c2;
  while( true ) {
    if (uVar1 == 0) {
      return -1;
    }
    if (((uint)puVar2[2] < param_1) && (param_1 < (uint)(puVar2[2] + puVar2[3]))) break;
    puVar2 = puVar2 + 5;
    iVar3 = iVar3 + 1;
    uVar1 = uVar1 - 1;
  }
  return iVar3;
}

