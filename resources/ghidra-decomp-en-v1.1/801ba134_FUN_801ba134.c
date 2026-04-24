// Function: FUN_801ba134
// Entry: 801ba134
// Size: 308 bytes

void FUN_801ba134(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int iVar1;
  uint uVar2;
  byte bVar4;
  undefined *puVar3;
  undefined8 uVar5;
  
  iVar1 = FUN_800e8a48();
  if (iVar1 == 0) {
    *(undefined4 *)(param_9 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_9 + 0xf4) = 2;
  }
  for (bVar4 = 1; bVar4 < 0x2e; bVar4 = bVar4 + 1) {
    FUN_800ea564();
  }
  puVar3 = *(undefined **)(param_9 + 0xb8);
  *puVar3 = (char)*(undefined2 *)(param_10 + 0x1a);
  puVar3[1] = *puVar3;
  uVar2 = FUN_80020078((int)*(short *)(param_10 + 0x1e));
  puVar3[2] = puVar3[2] | uVar2 != 0;
  *(undefined4 *)(puVar3 + 0xc) = 0xd7;
  puVar3[4] = 0;
  if ((puVar3[2] & 1) == 0) {
    *puVar3 = 3;
    puVar3[3] = uRam803dcb93;
    uVar5 = FUN_8004c360((double)FLOAT_803e5828,uRam803dcb93);
  }
  else {
    *puVar3 = 0;
    puVar3[3] = DAT_803dcb90;
    uVar5 = FUN_8004c360((double)FLOAT_803e5828,DAT_803dcb90);
  }
  FUN_8000a538((int *)0xdd,1);
  FUN_80088a84(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
  return;
}

