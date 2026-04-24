// Function: FUN_8000a380
// Entry: 8000a380
// Size: 408 bytes

void FUN_8000a380(undefined4 param_1,undefined4 param_2,uint param_3)

{
  bool bVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860dc();
  iVar4 = (int)uVar7;
  puVar2 = &DAT_80335dc0;
  iVar6 = 0xf;
  do {
    iVar5 = puVar2[3];
    if ((iVar5 != 0) &&
       ((*(byte *)((int)puVar2 + 0x11) + 1 & (uint)((ulonglong)uVar7 >> 0x20)) != 0)) {
      if (iVar4 == 2) {
        if (iVar5 != 2) {
          if ((iVar5 == 4) || (iVar5 == 5)) {
            puVar2[3] = 5;
          }
          else {
            uVar3 = param_3;
            if ((int)param_3 < 500) {
              uVar3 = 500;
            }
            FUN_80272720(0,uVar3 & 0xffff,puVar2[1],1);
            puVar2[3] = 2;
          }
        }
      }
      else if ((iVar4 < 2) && (0 < iVar4)) {
        iVar5 = FUN_80009b44();
        if (iVar5 == 0) {
          iVar5 = puVar2[3];
          if (iVar5 != 2) {
            if ((iVar5 == 4) || (iVar5 == 5)) {
              puVar2[3] = 5;
            }
            else {
              FUN_80272720(0,0xfa,puVar2[1],1);
              puVar2[3] = 2;
            }
          }
        }
        else if ((puVar2[3] == 4) || (puVar2[3] == 5)) {
          puVar2[3] = 5;
        }
        else {
          FUN_80272610(puVar2[1]);
          FUN_80023800(puVar2[2]);
          *puVar2 = 0xffffffff;
          puVar2[1] = 0xffffffff;
          puVar2[2] = 0;
          *(undefined *)(puVar2 + 4) = 0xff;
          puVar2[3] = 0;
          *(undefined2 *)((int)puVar2 + 0x12) = 0;
          puVar2[8] = FLOAT_803de560;
        }
      }
    }
    puVar2 = puVar2 + 9;
    bVar1 = iVar6 != 0;
    iVar6 = iVar6 + -1;
  } while (bVar1);
  FUN_80286128();
  return;
}

