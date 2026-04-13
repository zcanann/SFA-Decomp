// Function: FUN_802060cc
// Entry: 802060cc
// Size: 888 bytes

void FUN_802060cc(uint param_1)

{
  int iVar1;
  int *piVar2;
  uint uVar3;
  uint *puVar4;
  undefined4 local_48;
  int local_44;
  int local_40;
  undefined4 local_3c;
  undefined auStack_38 [16];
  float local_28;
  longlong local_20;
  
  puVar4 = *(uint **)(param_1 + 0xb8);
  local_48 = DAT_802c2c90;
  local_44 = DAT_802c2c94;
  local_40 = DAT_802c2c98;
  local_3c = DAT_802c2c9c;
  FUN_8000bb38(param_1,0x72);
  FUN_8005a310(param_1);
  if (*(char *)((int)puVar4 + 9) == '\x01') {
    local_28 = FLOAT_803e7078;
    *(undefined *)(puVar4 + 3) = *(undefined *)((int)puVar4 + 10);
    iVar1 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if ((iVar1 != 0) &&
       (*(char *)((int)puVar4 + 10) = '\x01' - *(char *)((int)puVar4 + 10),
       *(char *)((int)puVar4 + 10) != '\0')) {
      *(undefined2 *)((int)puVar4 + 6) = 2000;
    }
    if ((*(char *)((int)puVar4 + 10) != '\0') && (*(short *)((int)puVar4 + 6) != 0)) {
      local_20 = (longlong)(int)FLOAT_803dc074;
      *(short *)((int)puVar4 + 6) = *(short *)((int)puVar4 + 6) - (short)(int)FLOAT_803dc074;
      if (*(short *)((int)puVar4 + 6) < 1) {
        *(undefined2 *)((int)puVar4 + 6) = 0;
        *(undefined *)((int)puVar4 + 10) = 0;
      }
    }
    if (((*(char *)((int)puVar4 + 10) != '\0') && (*(short *)(puVar4 + 1) < 1)) &&
       (*(char *)((int)puVar4 + 0xb) != '\0')) {
      *(undefined *)((int)puVar4 + 0xb) = 0;
      FUN_8000bb38(param_1,0x80);
    }
    if (*(char *)((int)puVar4 + 10) != *(char *)(puVar4 + 3)) {
      if (*(char *)((int)puVar4 + 10) == '\0') {
        FUN_8000b7dc(param_1,0x40);
        (**(code **)(*DAT_803dd6fc + 0x18))(param_1);
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
        if ((*puVar4 != 0xffffffff) && (uVar3 = FUN_80020078(*puVar4), uVar3 != 0)) {
          FUN_800201ac(*puVar4,0);
        }
        if ((DAT_803de968 == '\x01') && (*(char *)((int)puVar4 + 0xd) == '\0')) {
          DAT_803de968 = '\0';
        }
        if (((DAT_803de968 == '\x02') && (*(char *)((int)puVar4 + 0xd) == '\x01')) &&
           (uVar3 = FUN_80020078(0x5e2), uVar3 == 0)) {
          FUN_800201ac(0x5e2,0);
          DAT_803de968 = '\0';
        }
      }
      else {
        piVar2 = (int *)FUN_80013ee8(0x69);
        local_40 = (uint)*(byte *)((int)puVar4 + 0xd) * 2;
        local_44 = local_40 + 0x19d;
        local_40 = local_40 + 0x19e;
        (**(code **)(*piVar2 + 4))(param_1,1,auStack_38,0x10004,0xffffffff,&local_48);
        FUN_80013e4c((undefined *)piVar2);
        iVar1 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x1a3,0,0,0xffffffff,0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < 100);
        if ((*puVar4 != 0xffffffff) && (uVar3 = FUN_80020078(*puVar4), uVar3 == 0)) {
          FUN_800201ac(*puVar4,1);
        }
        if (((DAT_803de968 == '\0') && (*(char *)((int)puVar4 + 0xd) == '\0')) &&
           (uVar3 = FUN_80020078(*puVar4), uVar3 != 0)) {
          DAT_803de968 = '\x01';
        }
        if (((DAT_803de968 == '\x01') && (*(char *)((int)puVar4 + 0xd) == '\x01')) &&
           (uVar3 = FUN_80020078(*puVar4), uVar3 != 0)) {
          FUN_800201ac(0x5e2,1);
          DAT_803de968 = '\x02';
        }
        *(undefined *)((int)puVar4 + 0xb) = 1;
        *(undefined2 *)(puVar4 + 1) = 1;
      }
    }
  }
  return;
}

