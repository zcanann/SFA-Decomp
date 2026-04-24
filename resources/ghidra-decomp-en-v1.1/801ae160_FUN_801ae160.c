// Function: FUN_801ae160
// Entry: 801ae160
// Size: 380 bytes

void FUN_801ae160(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  undefined uVar1;
  bool bVar2;
  undefined2 *puVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  undefined2 *puVar7;
  undefined4 *puVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286830();
  puVar3 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  if (puVar3[0x23] == 0x373) {
    FUN_8003b9ec((int)puVar3);
  }
  else {
    uVar4 = FUN_80020078(0x6e);
    if ((uVar4 == 0) || (uVar4 = FUN_80020078(0x382), uVar4 != 0)) {
      puVar8 = *(undefined4 **)(puVar3 + 0x5c);
      puVar7 = (undefined2 *)*puVar8;
      bVar2 = false;
      if ((puVar7 != (undefined2 *)0x0) &&
         (iVar5 = (**(code **)(**(int **)(puVar7 + 0x34) + 0x38))(puVar7), iVar5 == 2)) {
        bVar2 = true;
      }
      if (bVar2) {
        puVar3[3] = puVar3[3] | 8;
        uVar6 = FUN_8005a310((int)puVar7);
        param_6 = (char)uVar6;
        FUN_801add98(puVar3,puVar7,(int)uVar9,param_3,param_4,param_5,param_6,
                     (uint)*(byte *)(puVar8 + 8),1);
      }
      else {
        puVar3[3] = puVar3[3] & 0xfff7;
      }
      if ((param_6 != '\0') && (*(char *)(puVar8 + 8) != '\0')) {
        uVar1 = *(undefined *)((int)puVar3 + 0x37);
        if (bVar2) {
          *(char *)((int)puVar3 + 0x37) = *(char *)(puVar8 + 8);
        }
        FUN_8003b9ec((int)puVar3);
        FUN_80038524(puVar3,1,(float *)(puVar8 + 5),puVar8 + 6,(float *)(puVar8 + 7),0);
        *(undefined *)((int)puVar3 + 0x37) = uVar1;
      }
    }
  }
  FUN_8028687c();
  return;
}

