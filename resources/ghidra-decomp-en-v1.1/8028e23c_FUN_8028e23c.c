// Function: FUN_8028e23c
// Entry: 8028e23c
// Size: 112 bytes

undefined4 FUN_8028e23c(void)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 uVar3;
  
  puVar1 = (undefined4 *)&DAT_80332fe0;
  uVar3 = 0;
  while( true ) {
    if (puVar1 == (undefined4 *)0x0) break;
    if (((*(ushort *)(puVar1 + 1) >> 6 & 7) != 0) && (iVar2 = FUN_8028f380(puVar1), iVar2 != 0)) {
      uVar3 = 0xffffffff;
    }
    puVar1 = (undefined4 *)puVar1[0x13];
  }
  return uVar3;
}

