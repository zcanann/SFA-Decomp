// Function: FUN_8002ba84
// Entry: 8002ba84
// Size: 64 bytes

undefined4 FUN_8002ba84(void)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int local_8 [2];
  
  puVar1 = FUN_80037048(1,local_8);
  if (local_8[0] == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = *puVar1;
  }
  return uVar2;
}

