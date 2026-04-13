// Function: FUN_801291ac
// Entry: 801291ac
// Size: 812 bytes

void FUN_801291ac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int iVar2;
  byte bVar4;
  uint uVar3;
  undefined4 in_r9;
  undefined4 in_r10;
  byte bVar5;
  int iVar6;
  ushort *puVar7;
  double dVar8;
  undefined8 uVar9;
  double dVar10;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  byte abStack_4c [36];
  longlong local_28;
  
  FUN_8028683c();
  local_58 = DAT_802c2920;
  local_54 = DAT_802c2924;
  local_50 = DAT_802c2928;
  if (DAT_803de400 == '\0') {
    FUN_80077318((double)FLOAT_803e2dc0,(double)FLOAT_803e2ac0,DAT_803a9638,0xff,0x100);
    FUN_80076998((double)FLOAT_803e2d48,(double)FLOAT_803e2ac0,DAT_803a9644,0xff,0x100,600,5,0);
    FUN_80076998((double)FLOAT_803e2dc0,(double)FLOAT_803e2d10,DAT_803a963c,0xff,0x100,5,400,0);
    FUN_80076998((double)FLOAT_803e2d48,(double)FLOAT_803e2d10,DAT_803a9640,0xff,0x100,600,400,0);
    FUN_80076998((double)FLOAT_803e2d48,(double)FLOAT_803e2dc4,DAT_803a9644,0xff,0x100,600,5,2);
    FUN_80076998((double)FLOAT_803e2dc8,(double)FLOAT_803e2d10,DAT_803a963c,0xff,0x100,5,400,1);
    FUN_80076998((double)FLOAT_803e2dc8,(double)FLOAT_803e2dc4,DAT_803a9638,0xff,0x100,5,5,3);
    FUN_80076998((double)FLOAT_803e2dc8,(double)FLOAT_803e2ac0,DAT_803a9638,0xff,0x100,5,5,1);
    FUN_80076998((double)FLOAT_803e2dc0,(double)FLOAT_803e2dc4,DAT_803a9638,0xff,0x100,5,5,2);
    DAT_803de466 = DAT_803de466 + DAT_803dc71c;
    dVar8 = (double)FUN_80293bc4();
    dVar10 = (double)FLOAT_803dc720;
    iVar6 = (int)(dVar10 * dVar8 + (double)FLOAT_803dc724);
    local_28 = (longlong)iVar6;
    bVar4 = (byte)iVar6;
    if (DAT_803de3db == '\x01') {
      bVar5 = bVar4;
      bVar4 = 0xff;
    }
    else {
      bVar5 = 0xff;
    }
    FUN_80016848(dVar8,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,0x2f7,0,5);
    uVar9 = FUN_80019940(bVar5,bVar5,bVar5,0xff);
    FUN_800168a8(uVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,0x2f8);
    uVar9 = FUN_80019940(bVar4,bVar4,bVar4,0xff);
    FUN_800168a8(uVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,0x2fb);
    uVar9 = FUN_80019940(0xff,0xff,0xff,0xff);
    iVar6 = 0;
    puVar7 = (ushort *)&local_58;
    do {
      uVar3 = FUN_80020078((uint)*puVar7);
      if (iVar6 == 0) {
        uVar9 = FUN_8001741c(6);
        uVar9 = FUN_800168a8(uVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,0x2fa);
      }
      else if (iVar6 == 3) {
        uVar9 = FUN_8001741c(7);
        uVar9 = FUN_800168a8(uVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,0x2fa);
      }
      iVar1 = (int)uVar3 / 6000 + ((int)uVar3 >> 0x1f);
      iVar1 = iVar1 - (iVar1 >> 0x1f);
      iVar2 = (int)uVar3 / 100 + ((int)uVar3 >> 0x1f);
      FUN_8028fde8(uVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,(int)abStack_4c,
                   s__02d__02d__02d_8031cd70,iVar1,(iVar2 - (iVar2 >> 0x1f)) + iVar1 * -0x3c,
                   uVar3 + (iVar2 - (iVar2 >> 0x1f)) * -100,iVar1 * 0x3c,in_r9,in_r10);
      uVar9 = FUN_80016258(abStack_4c);
      puVar7 = puVar7 + 1;
      iVar6 = iVar6 + 1;
    } while (iVar6 < 6);
    FUN_8001741c(0xff);
  }
  FUN_80286888();
  return;
}

