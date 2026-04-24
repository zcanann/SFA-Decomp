// Function: FUN_8008fb90
// Entry: 8008fb90
// Size: 496 bytes

void FUN_8008fb90(float *param_1)

{
  int iVar1;
  uint uVar2;
  float *pfVar3;
  double dVar4;
  uint3 local_58;
  undefined4 local_54;
  undefined4 local_50;
  int local_4c;
  float afStack_48 [3];
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  longlong local_10;
  
  local_54 = DAT_803dfe1c;
  local_30 = *param_1 - FLOAT_803dda58;
  local_2c = param_1[1];
  local_28 = param_1[2] - FLOAT_803dda5c;
  local_3c = param_1[3] - FLOAT_803dda58;
  local_38 = param_1[4];
  local_34 = param_1[5] - FLOAT_803dda5c;
  uVar2 = (uint)(*(ushort *)((int)param_1 + 0x22) >> 1);
  if (uVar2 < *(ushort *)(param_1 + 8)) {
    uStack_1c = (uint)*(ushort *)((int)param_1 + 0x22) - (uint)*(ushort *)(param_1 + 8) ^ 0x80000000
    ;
    local_20 = 0x43300000;
    uStack_14 = uVar2 ^ 0x80000000;
    local_18 = 0x43300000;
    iVar1 = (int)((FLOAT_803dfe54 *
                  (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803dfe28)) /
                 (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803dfe28));
    local_10 = (longlong)iVar1;
    FUN_80079b60(0x80,0x80,0xff,(char)iVar1);
  }
  else {
    FUN_80079b60(0x80,0x80,0xff,0xff);
  }
  FUN_80259288(0);
  FUN_8000fb20();
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  FUN_80079b3c();
  FUN_8007965c();
  FUN_80079980();
  FUN_80078a58();
  FUN_8006c698(&local_4c);
  FUN_8004c460(local_4c,0);
  _local_58 = local_54;
  dVar4 = (double)FLOAT_803dfe20;
  FUN_8025ca38(dVar4,dVar4,dVar4,dVar4,0,&local_58);
  FUN_8000f584();
  pfVar3 = (float *)FUN_8000f56c();
  FUN_8025d80c(pfVar3,0);
  FUN_8025d888(0);
  local_50 = FUN_80293520();
  if (*(short *)(param_1 + 9) == -1) {
    *(short *)(param_1 + 9) = (short)local_50;
  }
  FUN_80293544((uint)*(ushort *)(param_1 + 9));
  FUN_80247eb8(&local_3c,&local_30,afStack_48);
  FUN_80247f54(afStack_48);
  FUN_8008f554((double)param_1[6],(double)param_1[7],&local_30,&local_3c,
               (uint)*(byte *)((int)param_1 + 0x26),&local_50,0,(uint)*(byte *)((int)param_1 + 0x27)
              );
  FUN_80293544(local_50);
  return;
}

