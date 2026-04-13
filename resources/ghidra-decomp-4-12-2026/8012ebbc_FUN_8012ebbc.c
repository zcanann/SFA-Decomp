// Function: FUN_8012ebbc
// Entry: 8012ebbc
// Size: 252 bytes

void FUN_8012ebbc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined *puVar1;
  byte *pbVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  undefined8 uVar7;
  int local_18 [4];
  
  puVar1 = FUN_80017400(0x7c);
  if ((DAT_803dc6d8 != 0xffff) && ((int)DAT_803de550 != 0)) {
    uVar4 = 0xff;
    uVar5 = (int)DAT_803de550 & 0xff;
    uVar7 = FUN_80019940(0xff,0xff,0xff,(byte)DAT_803de550);
    if (DAT_803de54a == -1) {
      puVar1[0x1e] = (char)DAT_803de550;
      FUN_80016c50((uint)DAT_803dc6d8,&DAT_803aa0a0);
    }
    else {
      pbVar2 = (byte *)FUN_800191fc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    (uint)DAT_803dc6d8,DAT_803aa0a4,uVar4,uVar5,in_r7,in_r8,in_r9,
                                    in_r10);
      iVar3 = FUN_80015cf0(pbVar2,local_18);
      iVar6 = 0x7a;
      if ((iVar3 == 0xf8f7) && (iVar3 = FUN_80015cf0(pbVar2 + local_18[0],local_18), iVar3 == 5)) {
        iVar6 = 0x7c;
      }
      puVar1 = FUN_80017400(iVar6);
      puVar1[0x1e] = (char)DAT_803de550;
      FUN_800161c4(pbVar2,iVar6);
    }
  }
  return;
}

