// Function: FUN_8005e730
// Entry: 8005e730
// Size: 588 bytes

void FUN_8005e730(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  byte local_68;
  byte local_67;
  byte local_66;
  undefined uStack101;
  int local_64;
  undefined auStack96 [4];
  undefined auStack92 [4];
  undefined auStack88 [8];
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  
  uVar4 = FUN_802860d4();
  iVar2 = (int)((ulonglong)uVar4 >> 0x20);
  iVar1 = (int)uVar4;
  uStack76 = (int)*(short *)(iVar2 + 6) >> 3 ^ 0x80000000;
  local_50 = 0x43300000;
  uStack68 = (int)*(short *)(iVar2 + 8) >> 3 ^ 0x80000000;
  local_48 = 0x43300000;
  uStack60 = (int)*(short *)(iVar2 + 10) >> 3 ^ 0x80000000;
  local_40 = 0x43300000;
  uStack52 = (int)*(short *)(iVar2 + 0xc) >> 3 ^ 0x80000000;
  local_38 = 0x43300000;
  uStack44 = (int)*(short *)(iVar2 + 0xe) >> 3 ^ 0x80000000;
  local_30 = 0x43300000;
  uStack36 = (int)*(short *)(iVar2 + 0x10) >> 3 ^ 0x80000000;
  local_28 = 0x43300000;
  FUN_8001e928((double)((float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803debc0) +
                        *(float *)(iVar1 + 0x18) + FLOAT_803dcdd8),
               (double)((float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803debc0) +
                       *(float *)(iVar1 + 0x28)),
               (double)((float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803debc0) +
                        *(float *)(iVar1 + 0x38) + FLOAT_803dcddc),
               (double)((float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803debc0) +
                        *(float *)(iVar1 + 0x18) + FLOAT_803dcdd8),
               (double)((float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803debc0) +
                       *(float *)(iVar1 + 0x28)),
               (double)((float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803debc0) +
                        *(float *)(iVar1 + 0x38) + FLOAT_803dcddc),&DAT_803dce20,2,&local_64);
  FUN_800528f0();
  FUN_8004ce0c(param_3);
  puVar3 = (undefined4 *)&DAT_803dce20;
  for (iVar2 = 0; iVar2 < local_64; iVar2 = iVar2 + 1) {
    FUN_8001dacc(*puVar3,&local_68,&local_67,&local_66,&uStack101);
    local_68 = (char)((int)(uint)local_68 >> 1) + (char)((int)(uint)local_68 >> 2);
    local_67 = (char)((int)(uint)local_67 >> 1) + (char)((int)(uint)local_67 >> 2);
    local_66 = (char)((int)(uint)local_66 >> 1) + (char)((int)(uint)local_66 >> 2);
    FUN_8001dd50(*puVar3,auStack96,auStack92,auStack88);
    FUN_8001dd48(*puVar3);
    FUN_8004fa30(&local_68,auStack96);
    puVar3 = puVar3 + 1;
  }
  FUN_800528bc();
  FUN_80259e58(1);
  FUN_80258b24(2);
  FUN_80070310(1,3,0);
  FUN_800702b8(1);
  FUN_8025c584(1,4,5,5);
  FUN_8025bff0(7,0,0,7,0);
  FUN_80286120();
  return;
}

