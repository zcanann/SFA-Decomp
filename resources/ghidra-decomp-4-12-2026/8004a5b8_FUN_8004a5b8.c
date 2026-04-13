// Function: FUN_8004a5b8
// Entry: 8004a5b8
// Size: 304 bytes

undefined4 FUN_8004a5b8(char param_1)

{
  bool bVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  undefined4 local_28;
  undefined4 uStack_24;
  undefined4 local_20;
  undefined4 local_1c;
  uint local_18;
  
  uVar2 = 1;
  FUN_8007048c(1,3,1);
  uVar4 = FUN_8025ce2c(1);
  FUN_80258a04((int)((ulonglong)uVar4 >> 0x20),(int)uVar4,uVar2);
  puVar3 = &local_28;
  FUN_80256b2c(DAT_803dd954,&uStack_24,puVar3);
  local_20 = local_28;
  local_1c = 0;
  local_18 = DAT_803dd950;
  FUN_80243e74();
  FUN_8001383c((short *)&DAT_80360390,(uint)&local_20);
  if (DAT_803dd927 == '\0') {
    FUN_80256c08(local_28);
    DAT_803dd927 = '\x01';
  }
  FUN_80243e9c();
  FUN_80258b60((uint)DAT_803dc22e);
  uVar4 = FUN_80259a9c(DAT_803dd950,1);
  FUN_80258a04((int)((ulonglong)uVar4 >> 0x20),(int)uVar4,(uint)puVar3);
  DAT_803dc22e = DAT_803dc22e + 1;
  bVar1 = DAT_803dd950 == DAT_803dd96c;
  DAT_803dd950 = DAT_803dd96c;
  if (bVar1) {
    DAT_803dd950 = DAT_803dd968;
  }
  if (((param_1 != '\0') && (DAT_803dc22c != '\0')) &&
     (DAT_803dc22c = DAT_803dc22c + -1, DAT_803dc22c == '\0')) {
    FUN_8024de40(0);
    DAT_803dc22c = '\0';
  }
  return 0;
}

