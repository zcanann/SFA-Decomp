// Function: FUN_801299d4
// Entry: 801299d4
// Size: 196 bytes

undefined4 FUN_801299d4(byte param_1,uint param_2,uint param_3,char param_4)

{
  byte bVar1;
  uint uVar2;
  undefined1 *puVar3;
  int iVar4;
  
  puVar3 = FUN_800e8d30();
  uVar2 = countLeadingZeros(10 - (param_3 & 0xff));
  iVar4 = FUN_800e8b38((uint)param_1,(byte)(uVar2 >> 5),param_2,puVar3);
  DAT_803dc6f9 = (undefined)iVar4;
  if (((param_4 == '\x02') || (bVar1 = DAT_803dc6f8, param_4 == '\x01')) &&
     (bVar1 = param_1, DAT_803dc6f8 == 0xff)) {
    FUN_8000a538((int *)0x23,1);
    FUN_800207ac(1);
    FUN_800206ec(0xff);
    bVar1 = param_1;
  }
  DAT_803dc6f8 = bVar1;
  return 1;
}

