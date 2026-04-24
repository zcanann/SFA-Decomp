// Function: FUN_8028d3ec
// Entry: 8028d3ec
// Size: 188 bytes

/* WARNING: Removing unreachable block (ram,0x8028d46c) */

undefined4 FUN_8028d3ec(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  char cVar2;
  int iVar1;
  byte bVar3;
  undefined4 local_18 [4];
  
  cVar2 = FUN_8028d34c();
  if ((cVar2 != '\0') && (iVar1 = FUN_8028a648(), iVar1 != 0)) {
    local_18[0] = *param_3;
    bVar3 = FUN_8028c970(0xd1,0,local_18,param_2);
    *param_3 = local_18[0];
    if (bVar3 != 1) {
      if (bVar3 == 0) {
        return 0;
      }
      if (bVar3 < 3) {
        return 2;
      }
    }
  }
  return 1;
}

