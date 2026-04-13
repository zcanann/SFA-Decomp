// Function: FUN_801af940
// Entry: 801af940
// Size: 476 bytes

void FUN_801af940(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  int iVar2;
  char cVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint *puVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  undefined8 extraout_f1_00;
  
  puVar4 = *(uint **)(param_9 + 0xb8);
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x6000;
  uVar1 = FUN_80020078(0x36e);
  if (uVar1 != 0) {
    *puVar4 = *puVar4 & 4;
  }
  uVar1 = FUN_80020078(0x543);
  if (uVar1 == 0) {
    uVar1 = FUN_80020078(0x387);
    if (uVar1 == 0) {
      uVar1 = FUN_80020078(0x386);
      if (uVar1 == 0) {
        uVar1 = FUN_80020078(0x385);
        if (uVar1 == 0) {
          uVar1 = FUN_80020078(900);
          if (uVar1 != 0) {
            *(byte *)(puVar4 + 1) = *(byte *)(puVar4 + 1) & 199 | 8;
          }
        }
        else {
          *(byte *)(puVar4 + 1) = *(byte *)(puVar4 + 1) & 199 | 0x10;
        }
      }
      else {
        *(byte *)(puVar4 + 1) = *(byte *)(puVar4 + 1) & 199 | 0x18;
      }
    }
    else {
      *(byte *)(puVar4 + 1) = *(byte *)(puVar4 + 1) & 199 | 0x20;
    }
  }
  else {
    *(byte *)(puVar4 + 1) = *(byte *)(puVar4 + 1) & 199 | 0x28;
  }
  FUN_80088afc(&DAT_80324550,&DAT_80324518,&DAT_80324588,&DAT_803245c0);
  iVar2 = FUN_800e8a48();
  if (iVar2 == 0) {
    cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0);
    uVar5 = extraout_f1_00;
    if (cVar3 == '\0') {
      uVar5 = FUN_80088a84(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           0x1f);
    }
    FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x23c,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  else {
    cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0);
    uVar5 = extraout_f1;
    if (cVar3 == '\0') {
      uVar5 = FUN_80088a84(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3f)
      ;
    }
    FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x23c,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  *(undefined2 *)(puVar4 + 3) = 0;
  return;
}

