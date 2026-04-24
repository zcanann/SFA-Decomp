// Function: FUN_8008f904
// Entry: 8008f904
// Size: 496 bytes

void FUN_8008f904(float *param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  double dVar4;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined auStack72 [12];
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  longlong local_10;
  
  local_54 = DAT_803df19c;
  local_30 = *param_1 - FLOAT_803dcdd8;
  local_2c = param_1[1];
  local_28 = param_1[2] - FLOAT_803dcddc;
  local_3c = param_1[3] - FLOAT_803dcdd8;
  local_38 = param_1[4];
  local_34 = param_1[5] - FLOAT_803dcddc;
  uVar2 = (uint)(*(ushort *)((int)param_1 + 0x22) >> 1);
  if (uVar2 < *(ushort *)(param_1 + 8)) {
    uStack28 = (uint)*(ushort *)((int)param_1 + 0x22) - (uint)*(ushort *)(param_1 + 8) ^ 0x80000000;
    local_20 = 0x43300000;
    uStack20 = uVar2 ^ 0x80000000;
    local_18 = 0x43300000;
    iVar1 = (int)((FLOAT_803df1d4 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803df1a8)
                  ) / (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803df1a8));
    local_10 = (longlong)iVar1;
    FUN_800799e4(0x80,0x80,0xff,iVar1);
  }
  else {
    FUN_800799e4(0x80,0x80,0xff,0xff);
  }
  FUN_80258b24(0);
  FUN_8000fb00();
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  FUN_800799c0();
  FUN_800794e0();
  FUN_80079804();
  FUN_800788dc();
  FUN_8006c51c(&local_4c);
  FUN_8004c2e4(local_4c,0);
  local_58 = local_54;
  dVar4 = (double)FLOAT_803df1a0;
  FUN_8025c2d4(dVar4,dVar4,dVar4,dVar4,0,&local_58);
  FUN_8000f564();
  uVar3 = FUN_8000f54c();
  FUN_8025d0a8(uVar3,0);
  FUN_8025d124(0);
  local_50 = FUN_80292dc0();
  if (*(short *)(param_1 + 9) == -1) {
    *(short *)(param_1 + 9) = (short)local_50;
  }
  FUN_80292de4(*(undefined2 *)(param_1 + 9));
  FUN_80247754(&local_3c,&local_30,auStack72);
  FUN_802477f0(auStack72);
  FUN_8008f2c8((double)param_1[6],(double)param_1[7],&local_30,&local_3c,
               *(undefined *)((int)param_1 + 0x26),&local_50,0,*(undefined *)((int)param_1 + 0x27));
  FUN_80292de4(local_50);
  return;
}

