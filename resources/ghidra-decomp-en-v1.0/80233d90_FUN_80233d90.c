// Function: FUN_80233d90
// Entry: 80233d90
// Size: 692 bytes

void FUN_80233d90(short *param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  double dVar3;
  undefined local_38;
  undefined local_37;
  undefined local_36 [2];
  float local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  local_34 = DAT_802c25f8;
  local_30 = DAT_802c25fc;
  local_2c = DAT_802c2600;
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  if (*piVar2 == 0) {
    iVar1 = FUN_8001f4c8(param_1,1);
    *piVar2 = iVar1;
  }
  if (*piVar2 != 0) {
    FUN_8001db2c(*piVar2,2);
    FUN_8001db34(*piVar2,*(undefined *)(param_2 + 0x1d));
    dVar3 = (double)FLOAT_803e7230;
    FUN_8001dd88(dVar3,dVar3,dVar3,*piVar2);
    if ((*(byte *)(param_2 + 0x2a) & 1) == 0) {
      FUN_8001daf0(*piVar2,*(undefined *)(param_2 + 0x1a),*(undefined *)(param_2 + 0x1b),
                   *(undefined *)(param_2 + 0x1c),0xff);
      FUN_8001dab8(*piVar2,*(undefined *)(param_2 + 0x27),*(undefined *)(param_2 + 0x28),
                   *(undefined *)(param_2 + 0x29),0xff);
    }
    else {
      FUN_800898c8(0,local_36,&local_37,&local_38);
      FUN_8001daf0(*piVar2,local_36[0],local_37,local_38,0xff);
      FUN_8001dab8(*piVar2,local_36[0],local_37,local_38,0xff);
    }
    uStack36 = (uint)*(ushort *)(param_2 + 0x22);
    local_28 = 0x43300000;
    uStack28 = (uint)*(ushort *)(param_2 + 0x24);
    local_20 = 0x43300000;
    FUN_8001dc38((double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e7248),
                 (double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e7248),*piVar2);
    uStack20 = (uint)*(byte *)(param_2 + 0x20);
    if (0x59 < uStack20) {
      uStack20 = 0x5a;
    }
    uStack20 = uStack20 ^ 0x80000000;
    local_18 = 0x43300000;
    FUN_8001da60((double)(float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e7238),*piVar2,
                 *(undefined *)(param_2 + 0x21));
    FUN_8001db6c((double)FLOAT_803e7230,*piVar2,*(undefined *)(param_2 + 0x30));
    *(undefined *)(piVar2 + 1) = *(undefined *)(param_2 + 0x30);
    FUN_8001d620(*piVar2,*(undefined *)(param_2 + 0x26),(int)*(short *)(param_2 + 0x2e));
    FUN_8001dc90((double)local_34,(double)local_30,(double)local_2c,*piVar2);
    if (*(char *)(param_2 + 0x21) == '\0') {
      FUN_8002b884(param_1,0);
    }
    else {
      FUN_8002b884(param_1,1);
    }
    if (*(char *)(param_2 + 0x3e) != '\0') {
      uStack20 = (uint)*(ushort *)(param_2 + 0x36);
      local_18 = 0x43300000;
      FUN_8001d730((double)(float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e7248),*piVar2,
                   *(undefined2 *)(param_2 + 0x38),*(undefined *)(param_2 + 0x3a),
                   *(undefined *)(param_2 + 0x3b),*(undefined *)(param_2 + 0x3c),
                   *(undefined *)(param_2 + 0x3d));
      FUN_8001d714((double)FLOAT_803e7240,*piVar2);
    }
    if (*(char *)(param_2 + 0x3f) != '\0') {
      FUN_8001dd40(*piVar2,1);
    }
    if (*(char *)(param_2 + 0x2c) != '\0') {
      FUN_8001db5c(*piVar2);
    }
  }
  FUN_80037200(param_1,0x35);
  return;
}

