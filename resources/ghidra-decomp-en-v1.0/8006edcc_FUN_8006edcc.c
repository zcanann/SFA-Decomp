// Function: FUN_8006edcc
// Entry: 8006edcc
// Size: 364 bytes

void FUN_8006edcc(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined8 extraout_f1;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined auStack72 [19];
  undefined auStack53 [8];
  char local_2d;
  
  uVar5 = FUN_802860dc();
  iVar1 = (int)uVar5;
  uVar4 = extraout_f1;
  FUN_800033a8(auStack72,0,0x1c);
  uVar2 = 0;
  iVar3 = 8;
  do {
    if ((iVar1 >> (uVar2 & 0x3f) & 1U) != 0) {
      auStack53[local_2d] = (char)uVar2;
      local_2d = local_2d + '\x01';
    }
    if ((iVar1 >> (uVar2 + 1 & 0x3f) & 1U) != 0) {
      auStack53[local_2d] = (char)(uVar2 + 1);
      local_2d = local_2d + '\x01';
    }
    if ((iVar1 >> (uVar2 + 2 & 0x3f) & 1U) != 0) {
      auStack53[local_2d] = (char)(uVar2 + 2);
      local_2d = local_2d + '\x01';
    }
    if ((iVar1 >> (uVar2 + 3 & 0x3f) & 1U) != 0) {
      auStack53[local_2d] = (char)(uVar2 + 3);
      local_2d = local_2d + '\x01';
    }
    uVar2 = uVar2 + 4;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  FUN_8006ef38(uVar4,param_2,(int)((ulonglong)uVar5 >> 0x20),auStack72,param_5,param_6,param_7);
  FUN_80286128();
  return;
}

