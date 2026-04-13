// Function: FUN_80234454
// Entry: 80234454
// Size: 692 bytes

void FUN_80234454(short *param_1,int param_2)

{
  int *piVar1;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar2;
  double dVar3;
  double dVar4;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined local_38;
  undefined local_37;
  undefined local_36 [2];
  float local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  local_34 = DAT_802c2d78;
  local_30 = DAT_802c2d7c;
  local_2c = DAT_802c2d80;
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  if (*piVar2 == 0) {
    piVar1 = FUN_8001f58c((int)param_1,'\x01');
    *piVar2 = (int)piVar1;
  }
  if (*piVar2 != 0) {
    FUN_8001dbf0(*piVar2,2);
    FUN_8001dbf8(*piVar2,(uint)*(byte *)(param_2 + 0x1d));
    dVar3 = (double)FLOAT_803e7ec8;
    FUN_8001de4c(dVar3,dVar3,dVar3,(int *)*piVar2);
    if ((*(byte *)(param_2 + 0x2a) & 1) == 0) {
      FUN_8001dbb4(*piVar2,*(undefined *)(param_2 + 0x1a),*(undefined *)(param_2 + 0x1b),
                   *(undefined *)(param_2 + 0x1c),0xff);
      FUN_8001db7c(*piVar2,*(undefined *)(param_2 + 0x27),*(undefined *)(param_2 + 0x28),
                   *(undefined *)(param_2 + 0x29),0xff);
    }
    else {
      FUN_80089b54(0,local_36,&local_37,&local_38);
      FUN_8001dbb4(*piVar2,local_36[0],local_37,local_38,0xff);
      FUN_8001db7c(*piVar2,local_36[0],local_37,local_38,0xff);
    }
    uStack_24 = (uint)*(ushort *)(param_2 + 0x22);
    local_28 = 0x43300000;
    uStack_1c = (uint)*(ushort *)(param_2 + 0x24);
    local_20 = 0x43300000;
    FUN_8001dcfc((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7ee0),
                 (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7ee0),*piVar2);
    uStack_14 = (uint)*(byte *)(param_2 + 0x20);
    if (0x59 < uStack_14) {
      uStack_14 = 0x5a;
    }
    uStack_14 = uStack_14 ^ 0x80000000;
    local_18 = 0x43300000;
    FUN_8001db24((double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e7ed0),*piVar2,
                 (uint)*(byte *)(param_2 + 0x21));
    FUN_8001dc30((double)FLOAT_803e7ec8,*piVar2,*(char *)(param_2 + 0x30));
    *(undefined *)(piVar2 + 1) = *(undefined *)(param_2 + 0x30);
    FUN_8001d6e4(*piVar2,(uint)*(byte *)(param_2 + 0x26),*(short *)(param_2 + 0x2e));
    dVar3 = (double)local_30;
    dVar4 = (double)local_2c;
    FUN_8001dd54((double)local_34,dVar3,dVar4,(int *)*piVar2);
    if (*(char *)(param_2 + 0x21) == '\0') {
      FUN_8002b95c((int)param_1,0);
    }
    else {
      FUN_8002b95c((int)param_1,1);
    }
    if (*(char *)(param_2 + 0x3e) != '\0') {
      uStack_14 = (uint)*(ushort *)(param_2 + 0x36);
      local_18 = 0x43300000;
      FUN_8001d7f4((double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e7ee0),dVar3,
                   dVar4,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar2,(uint)*(ushort *)(param_2 + 0x38),
                   (uint)*(byte *)(param_2 + 0x3a),(uint)*(byte *)(param_2 + 0x3b),
                   (uint)*(byte *)(param_2 + 0x3c),(uint)*(byte *)(param_2 + 0x3d),in_r9,in_r10);
      FUN_8001d7d8((double)FLOAT_803e7ed8,*piVar2);
    }
    if (*(char *)(param_2 + 0x3f) != '\0') {
      FUN_8001de04(*piVar2,1);
    }
    if (*(char *)(param_2 + 0x2c) != '\0') {
      FUN_8001dc20(*piVar2,*(char *)(param_2 + 0x2c));
    }
  }
  FUN_800372f8((int)param_1,0x35);
  return;
}

