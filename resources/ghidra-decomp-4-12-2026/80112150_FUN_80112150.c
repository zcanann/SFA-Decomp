// Function: FUN_80112150
// Entry: 80112150
// Size: 256 bytes

void FUN_80112150(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined2 uStack_1a;
  undefined4 local_18;
  undefined4 local_14;
  undefined2 local_10;
  
  local_18 = DAT_802c2910;
  local_14 = DAT_802c2914;
  local_10 = DAT_802c2918;
  if ((*(char *)(param_10 + 0x407) != *(char *)(param_10 + 0x409)) &&
     (*(char *)(param_9 + 0x36) != '\0')) {
    if (*(int *)(param_9 + 200) != 0) {
      param_1 = FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             *(int *)(param_9 + 200));
      *(undefined4 *)(param_9 + 200) = 0;
    }
    uVar1 = FUN_8002e144();
    if ((uVar1 & 0xff) == 0) {
      *(undefined *)(param_10 + 0x409) = 0;
    }
    else {
      if (0 < *(char *)(param_10 + 0x407)) {
        puVar2 = FUN_8002becc(0x18,(&uStack_1a)[*(char *)(param_10 + 0x407)]);
        uVar3 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                             4,0xff,0xffffffff,*(uint **)(param_9 + 0x30),in_r8,in_r9,in_r10);
        *(undefined4 *)(param_9 + 200) = uVar3;
        *(ushort *)(*(int *)(param_9 + 200) + 0xb0) = *(ushort *)(param_9 + 0xb0) & 7;
      }
      *(undefined *)(param_10 + 0x409) = *(undefined *)(param_10 + 0x407);
    }
  }
  return;
}

