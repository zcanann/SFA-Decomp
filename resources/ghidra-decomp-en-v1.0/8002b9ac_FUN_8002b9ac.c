// Function: FUN_8002b9ac
// Entry: 8002b9ac
// Size: 64 bytes

undefined4 FUN_8002b9ac(void)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int local_8 [2];
  
  puVar1 = (undefined4 *)FUN_80036f50(1,local_8);
  if (local_8[0] == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = *puVar1;
  }
  return uVar2;
}

