// Function: FUN_802101a4
// Entry: 802101a4
// Size: 644 bytes

void FUN_802101a4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  undefined uVar1;
  bool bVar2;
  undefined2 *puVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  undefined2 *puVar7;
  undefined4 *puVar8;
  undefined8 uVar9;
  float local_40 [2];
  undefined4 local_38;
  uint uStack_34;
  
  uVar9 = FUN_80286830();
  puVar3 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  local_40[0] = FLOAT_803e73a0;
  puVar8 = *(undefined4 **)(puVar3 + 0x5c);
  puVar7 = (undefined2 *)*puVar8;
  if (*(byte *)(puVar3 + 0x1b) < 5) {
    puVar8[0x2b] = FLOAT_803e7388;
  }
  bVar2 = false;
  if (((-1 < *(char *)(puVar8 + 0x29)) && (puVar7 != (undefined2 *)0x0)) &&
     (iVar4 = (**(code **)(**(int **)(puVar7 + 0x34) + 0x38))(puVar7), iVar4 == 2)) {
    bVar2 = true;
  }
  if (bVar2) {
    puVar3[3] = puVar3[3] | 8;
    uVar5 = FUN_8005a310((int)puVar7);
    param_6 = (char)uVar5;
    FUN_8020fc0c(puVar3,puVar7,(int)uVar9,param_3,param_4,param_5,param_6,
                 (uint)*(byte *)(puVar8 + 0x28),1);
  }
  else {
    puVar3[3] = puVar3[3] & 0xfff7;
  }
  if ((param_6 != '\0') && (*(char *)(puVar8 + 0x28) != '\0')) {
    uVar1 = *(undefined *)((int)puVar3 + 0x37);
    if (bVar2) {
      *(char *)((int)puVar3 + 0x37) = *(char *)(puVar8 + 0x28);
    }
    if (((*(char *)((int)puVar3 + 0xeb) == '\0') && (puVar3[0x23] == 0x389)) &&
       ((*(char *)((int)puVar8 + 0xaa) < '\0' &&
        (((iVar4 = FUN_80036f50(0x1e,puVar3,local_40), iVar4 != 0 &&
          (iVar6 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x24))(), iVar6 != 0)) &&
         (iVar6 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x20))(iVar4,0), iVar6 != 0)))))) {
      FUN_80037e24((int)puVar3,iVar4,0);
    }
    FUN_8003b9ec((int)puVar3);
    FUN_80038524(puVar3,1,(float *)(puVar8 + 6),puVar8 + 7,(float *)(puVar8 + 8),0);
    *(undefined *)((int)puVar3 + 0x37) = uVar1;
    if ((*(byte *)((int)puVar8 + 0xaa) >> 6 & 1) != 0) {
      if ((float)puVar8[0x2b] == FLOAT_803e7388) {
        *(byte *)((int)puVar8 + 0xaa) = *(byte *)((int)puVar8 + 0xaa) & 0xbf;
      }
      else {
        uStack_34 = 0xff - *(byte *)(puVar3 + 0x1b) ^ 0x80000000;
        local_38 = 0x43300000;
        puVar8[0x2b] = FLOAT_803e73a4 +
                       (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e73b0) /
                       FLOAT_803e73a8;
      }
      FUN_8009a010((double)FLOAT_803e73a4,(double)(float)puVar8[0x2b],puVar3,3,(int *)0x0);
    }
  }
  FUN_8028687c();
  return;
}

